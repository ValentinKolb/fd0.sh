package agent

import (
	"errors"
	"fmt"
	"net"
	"os"
	"time"
)

// Client is a thin RPC wrapper over the agent socket. One Client per fd0
// CLI invocation; a fresh net.Conn is dialed per call (frames are tiny).
type Client struct {
	sock string
}

// NewClient resolves the socket path via fdhome.
func NewClient(sock string) *Client { return &Client{sock: sock} }

// IsRunning probes whether the agent is up. We need TWO checks because
// a Unix domain socket file persists on disk after the listening process
// dies (e.g. `kill -9` of fd0-agent leaves the socket inode behind):
//
//  1. The path exists and is a socket inode (cheap stat).
//  2. We can actually connect — i.e. some process is listening.
//
// Without (2), `RunUnlock` would see a stale socket, skip the spawn,
// and then fail with "connection refused" when it tries to talk. (2)
// uses a tight 200ms timeout so a healthy agent answers quickly while
// stale sockets don't block the call.
func (c *Client) IsRunning() bool {
	st, err := os.Stat(c.sock)
	if err != nil {
		return false
	}
	if st.Mode()&os.ModeSocket == 0 {
		return false
	}
	conn, err := net.DialTimeout("unix", c.sock, 200*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// Status calls OpStatus.
//
// SECURITY (codex audit 🟡 client.go:53): every accessor below
// validates the expected response arm is non-nil before
// dereferencing. A malformed / old / hostile agent response could
// otherwise return nil and panic at the caller.
func (c *Client) Status() (*StatusResp, error) {
	r, err := c.do(&Request{Op: OpStatus})
	if err != nil {
		return nil, err
	}
	if r.Status == nil {
		return nil, errors.New("agent: malformed Status response")
	}
	return r.Status, nil
}

// Unlock calls OpUnlock. userChainPath is REQUIRED for the
// rollback-detection check on the agent side; pass an empty string
// only in tests that don't care.
func (c *Client) Unlock(vaultPath, userChainPath, methodType string, passphrase []byte) (*UnlockResp, error) {
	r, err := c.do(&Request{Op: OpUnlock, Unlock: &UnlockReq{
		VaultPath: vaultPath, UserChainPath: userChainPath, MethodType: methodType, Passphrase: passphrase,
	}})
	if err != nil {
		return nil, err
	}
	if r.Unlock == nil {
		return nil, errors.New("agent: malformed Unlock response")
	}
	return r.Unlock, nil
}

// Lock calls OpLock.
func (c *Client) Lock() error { _, err := c.do(&Request{Op: OpLock}); return err }

// Sign calls OpSign.
func (c *Client) Sign(payload []byte) ([]byte, error) {
	r, err := c.do(&Request{Op: OpSign, Sign: &SignReq{Payload: payload}})
	if err != nil {
		return nil, err
	}
	if r.Sign == nil {
		return nil, errors.New("agent: malformed Sign response")
	}
	return r.Sign.Signature, nil
}

// OpenSeal calls OpOpenSeal.
func (c *Client) OpenSeal(sealed []byte) ([]byte, error) {
	r, err := c.do(&Request{Op: OpOpenSeal, OpenSeal: &OpenSealReq{Sealed: sealed}})
	if err != nil {
		return nil, err
	}
	if r.OpenSeal == nil {
		return nil, errors.New("agent: malformed OpenSeal response")
	}
	return r.OpenSeal.Plain, nil
}

// GetBody calls OpGetBody.
func (c *Client) GetBody() (*GetBodyResp, error) {
	r, err := c.do(&Request{Op: OpGetBody})
	if err != nil {
		return nil, err
	}
	if r.GetBody == nil {
		return nil, errors.New("agent: malformed GetBody response")
	}
	return r.GetBody, nil
}

// RecoveryExport calls OpRecoveryExport. Returns the AEAD ciphertext of
// super_priv encrypted under K_recovery.
func (c *Client) RecoveryExport(unlockKey, salt, nonce, userSuperPub []byte) ([]byte, error) {
	r, err := c.do(&Request{Op: OpRecoveryExport, RecoveryExport: &RecoveryExportReq{
		UnlockKey: unlockKey, UserSuperPub: userSuperPub, Nonce: nonce,
	}})
	if err != nil {
		return nil, err
	}
	if r.RecoveryExport == nil {
		return nil, errors.New("agent: malformed RecoveryExport response")
	}
	_ = salt // salt lives in the RecoveryFile header; not needed by the agent
	return r.RecoveryExport.Encrypted, nil
}

// ReSeal calls OpReSeal. The agent re-encrypts the body under its cached
// payload_key; on-disk wraps are preserved unchanged.
func (c *Client) ReSeal(vaultPath string, redactedBody []byte) error {
	_, err := c.do(&Request{Op: OpReSeal, ReSeal: &ReSealReq{
		VaultPath: vaultPath, RedactedBody: redactedBody,
	}})
	return err
}

// EncryptSuperPriv calls OpEncryptSuperPriv. Returns the AEAD ciphertext for
// use in a new AuthMethod's encrypted_super_priv field.
func (c *Client) EncryptSuperPriv(unlockKey []byte, methodID string) ([]byte, error) {
	r, err := c.do(&Request{Op: OpEncryptSuperPriv, EncryptSuperPriv: &EncryptSuperPrivReq{
		UnlockKey: unlockKey, MethodID: methodID,
	}})
	if err != nil {
		return nil, err
	}
	if r.EncryptSuperPriv == nil {
		return nil, errors.New("agent: malformed EncryptSuperPriv response")
	}
	return r.EncryptSuperPriv.EncryptedSuperPriv, nil
}

// AddWrap calls OpAddWrap.
func (c *Client) AddWrap(vaultPath, methodID, methodType string, publicParams, unlockKey []byte) error {
	_, err := c.do(&Request{Op: OpAddWrap, AddWrap: &AddWrapReq{
		VaultPath: vaultPath, MethodID: methodID, MethodType: methodType,
		PublicParams: publicParams, UnlockKey: unlockKey,
	}})
	return err
}

// RemoveWrap calls OpRemoveWrap.
func (c *Client) RemoveWrap(vaultPath, methodID string) error {
	_, err := c.do(&Request{Op: OpRemoveWrap, RemoveWrap: &RemoveWrapReq{
		VaultPath: vaultPath, MethodID: methodID,
	}})
	return err
}

// do is one round-trip.
func (c *Client) do(req *Request) (*Response, error) {
	conn, err := dialUnix(c.sock)
	if err != nil {
		return nil, fmt.Errorf("agent: dial %s: %w", c.sock, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	if err := WriteFrame(conn, req); err != nil {
		return nil, err
	}
	var resp Response
	if err := ReadFrame(conn, &resp); err != nil {
		return nil, err
	}
	if resp.Err != "" {
		return nil, errors.New("agent: " + resp.Err)
	}
	return &resp, nil
}

