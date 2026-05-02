// fd0-test-bad-witness is a TEST-ONLY HTTP server that pretends to
// be an fd0-witness with programmable malicious behavior. Used by
// tests/integration_witness_malicious.sh to verify the client's
// cross-check correctly handles every kind of dishonest witness.
//
// Production deployments must NEVER ship this binary.
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/valentinkolb/fd0.sh/internal/proto"
	"github.com/valentinkolb/fd0.sh/internal/translog"
)

func main() {
	listen := flag.String("listen", ":15050", "HTTP listen address")
	upstream := flag.String("upstream", "", "Real fd0-server URL (for fetching honest STHs to forge from)")
	wKeyPath := flag.String("witness-key", "", "Witness ed25519 keyfile (will be created if missing)")
	srvKeyPath := flag.String("server-key", "", "Server ed25519 keyfile (used by malicious modes that need to forge server STHs)")
	mode := flag.String("mode", "passthrough", "Mode: passthrough | fork-cosign | wrong-chain-id | wrong-server-url | size-drift | garbage-cbor | always-409 | always-500 | wrong-witness-pub")
	flag.Parse()

	if *upstream == "" || *wKeyPath == "" || *srvKeyPath == "" {
		fmt.Fprintln(os.Stderr, "usage: fd0-test-bad-witness --upstream URL --witness-key KEY --server-key KEY [--mode MODE] [--listen ADDR]")
		os.Exit(2)
	}

	wPriv, wPub := loadOrGenKey(*wKeyPath)
	srvPriv, _ := loadKey(*srvKeyPath)

	bw := &badWitness{
		upstream:  *upstream,
		mode:      *mode,
		wPriv:     wPriv,
		wPub:      wPub,
		srvPriv:   srvPriv,
		http:      &http.Client{},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/witness/server-info", bw.handleServerInfo)
	mux.HandleFunc("/v1/witness/sth/", bw.handleSTH)
	log.Printf("bad-witness mode=%s listening on %s upstream=%s", *mode, *listen, *upstream)
	if err := http.ListenAndServe(*listen, mux); err != nil {
		log.Fatal(err)
	}
}

type badWitness struct {
	upstream string
	mode     string
	wPriv    ed25519.PrivateKey
	wPub     ed25519.PublicKey
	srvPriv  ed25519.PrivateKey
	http     *http.Client
}

func (b *badWitness) handleServerInfo(w http.ResponseWriter, r *http.Request) {
	pub := b.wPub
	if b.mode == "wrong-witness-pub" {
		// Reveal a different pub than what we actually sign with —
		// any client that uses this for first-contact would pin to
		// the wrong key. Tests that rely on operator-pin in TOML
		// won't be affected; this primarily exercises the
		// embedded-pub vs pin mismatch in WitnessedSTH responses.
		other := make([]byte, 32)
		for i := range other {
			other[i] = 0xAB
		}
		pub = other
	}
	body, _ := proto.Marshal(map[string]any{
		"witness_pub":     []byte(pub),
		"witness_pub_hex": fmt.Sprintf("%x", pub),
	})
	w.Header().Set("Content-Type", "application/cbor")
	w.WriteHeader(200)
	w.Write(body)
}

func (b *badWitness) handleSTH(w http.ResponseWriter, r *http.Request) {
	// Per-request log line — drives the malicious-witness
	// integration test's "this request actually hit me" assertion.
	log.Printf("REQUEST mode=%s path=%s", b.mode, r.URL.Path)
	// Parse server_b64 / chain / tree_size.
	rest := strings.TrimPrefix(r.URL.Path, "/v1/witness/sth/")
	parts := strings.SplitN(rest, "/", 2)
	if len(parts) != 2 {
		http.Error(w, "bad path", 400)
		return
	}
	serverURLBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		http.Error(w, "bad b64", 400)
		return
	}
	serverURL := string(serverURLBytes)
	chainID := parts[1]
	var size uint64
	if s := r.URL.Query().Get("tree_size"); s != "" {
		size, _ = strconv.ParseUint(s, 10, 64)
	} else {
		// "Latest" — we ask upstream for the current STH at any
		// size, then mutate per mode.
	}

	switch b.mode {
	case "always-409":
		http.Error(w, "fake equivocation", 409)
		return
	case "always-500":
		http.Error(w, "fake server error", 500)
		return
	case "garbage-cbor":
		w.Header().Set("Content-Type", "application/cbor")
		w.WriteHeader(200)
		w.Write([]byte{0xFF, 0xFE, 0xFD, 0x00, 0x42})
		return
	}

	// All other modes: fetch the upstream server's CURRENT STH and
	// use it as the basis for the forgery (so signatures verify
	// under the real server pub).
	sth, srvSTHsize, err := b.fetchUpstreamSTH(chainID)
	if err != nil {
		http.Error(w, fmt.Sprintf("upstream fetch failed: %v", err), 502)
		return
	}
	if size == 0 {
		size = srvSTHsize
	}

	// Now forge per mode.
	switch b.mode {
	case "passthrough":
		// Honest witness: verify nothing, just cosign the upstream
		// STH at its actual size and serve it.
		w_ := signAndSerialize(b.wPriv, sth, serverURL)
		writeWSTH(w, w_)

	case "fork-cosign":
		// Forge a server-signed STH at the requested size with a
		// TAMPERED root, then cosign it. The honest server is also
		// serving the CLIENT a (different) STH at the same size →
		// equivocation evidence.
		tampered := makeTamperedSTH(b.srvPriv, chainID, size, 0xEE)
		w_ := signAndSerialize(b.wPriv, tampered, serverURL)
		writeWSTH(w, w_)

	case "wrong-chain-id":
		// Cosign an STH whose embedded chain_id differs from what
		// the client asked about. (We forge a fresh STH for a
		// different chain_id; cosign embeds the wrong chain.)
		evilChain := "scope:s_evilevilevilevilevilevilev"
		evilSTH := makeTamperedSTH(b.srvPriv, evilChain, size, 0xCD)
		w_ := signAndSerialize(b.wPriv, evilSTH, serverURL)
		writeWSTH(w, w_)

	case "wrong-server-url":
		// Cosign with the WRONG server URL field — claims this
		// cosign is for a different server.
		w_ := signAndSerialize(b.wPriv, sth, serverURL+"_evil")
		writeWSTH(w, w_)

	case "size-drift":
		// Return a cosign for a DIFFERENT tree_size than asked.
		// Client should reject (size-drift skip path).
		other := makeTamperedSTH(b.srvPriv, chainID, size+1, 0xAA)
		w_ := signAndSerialize(b.wPriv, other, serverURL)
		writeWSTH(w, w_)

	case "wrong-witness-pub":
		// Cosign normally but stuff a DIFFERENT WitnessPub field
		// into the response. Client's pin check should reject.
		w_ := signAndSerialize(b.wPriv, sth, serverURL)
		other := make([]byte, 32)
		for i := range other {
			other[i] = 0xAB
		}
		w_.WitnessPub = other
		writeWSTH(w, w_)

	default:
		http.Error(w, "unknown mode "+b.mode, 500)
	}
}

func (b *badWitness) fetchUpstreamSTH(chainID string) (translog.STH, uint64, error) {
	endpoint := b.upstream + "/v1/sth/" + url.PathEscape(chainID)
	resp, err := b.http.Get(endpoint)
	if err != nil {
		return translog.STH{}, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return translog.STH{}, 0, fmt.Errorf("upstream %s", resp.Status)
	}
	body, _ := io.ReadAll(resp.Body)
	var sth translog.STH
	if err := proto.Unmarshal(body, &sth); err != nil {
		return translog.STH{}, 0, err
	}
	return sth, sth.Head.TreeSize, nil
}

func makeTamperedSTH(srvPriv ed25519.PrivateKey, chainID string, size uint64, fillByte byte) translog.STH {
	root := make([]byte, 32)
	for i := range root {
		root[i] = fillByte
	}
	if size == 0 {
		root = translog.EmptyRoot()
	}
	head := translog.TreeHead{ChainID: chainID, TreeSize: size, RootHash: root, Timestamp: 1}
	sth, err := translog.SignSTH(srvPriv, head)
	if err != nil {
		panic(err)
	}
	return sth
}

func signAndSerialize(wPriv ed25519.PrivateKey, sth translog.STH, serverURL string) translog.WitnessedSTH {
	w, err := translog.SignWitnessedSTH(wPriv, sth, serverURL)
	if err != nil {
		panic(err)
	}
	return w
}

func writeWSTH(w http.ResponseWriter, ws translog.WitnessedSTH) {
	body, err := proto.Marshal(ws)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "application/cbor")
	w.WriteHeader(200)
	w.Write(body)
}

// ---- key helpers ----

func loadKey(path string) (ed25519.PrivateKey, ed25519.PublicKey) {
	b, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("read key %s: %v", path, err)
	}
	if len(b) != ed25519.PrivateKeySize {
		log.Fatalf("key %s wrong size: %d (want %d)", path, len(b), ed25519.PrivateKeySize)
	}
	priv := ed25519.PrivateKey(b)
	return priv, priv.Public().(ed25519.PublicKey)
}

func loadOrGenKey(path string) (ed25519.PrivateKey, ed25519.PublicKey) {
	if b, err := os.ReadFile(path); err == nil {
		if len(b) == ed25519.PrivateKeySize {
			priv := ed25519.PrivateKey(b)
			return priv, priv.Public().(ed25519.PublicKey)
		}
	}
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(path, priv, 0600); err != nil {
		log.Fatal(err)
	}
	return priv, pub
}
