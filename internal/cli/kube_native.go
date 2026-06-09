package cli

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const envKubectlBinary = "FD0_KUBECTL"

func kubectlBin() string {
	if p := os.Getenv(envKubectlBinary); p != "" {
		return p
	}
	return "kubectl"
}

// kubectlMerge collapses fd0's rendered kubeconfig into the user's
// primary kubeconfig via
//   KUBECONFIG=<fd0>:<user> kubectl config view --merge --flatten > <user>
//
// The two-pass via a temp file is required because kubectl writes
// to the FIRST entry in $KUBECONFIG, and we want the merged output
// to end up in `<user>`, not in `<fd0>`.
func kubectlMerge(fd0Path, userPath string) error {
	if _, err := os.Stat(fd0Path); err != nil {
		return fmt.Errorf("kube merge: %s: %w", fd0Path, err)
	}
	if err := os.MkdirAll(filepath.Dir(userPath), 0o700); err != nil {
		return err
	}
	if _, err := exec.LookPath(kubectlBin()); err != nil {
		return fmt.Errorf("kubectl not on PATH (or FD0_KUBECTL not set): %w", err)
	}

	// Build the merge env. If user file is missing yet, that's fine
	// — kubectl tolerates non-existent entries.
	envKUBECONFIG := fd0Path
	if _, err := os.Stat(userPath); err == nil {
		envKUBECONFIG = fd0Path + string(os.PathListSeparator) + userPath
	}

	cmd := exec.Command(kubectlBin(), "config", "view", "--merge", "--flatten", "--raw")
	cmd.Env = append(os.Environ(), "KUBECONFIG="+envKUBECONFIG)
	// Cap stderr at 8 KiB: a chatty plugin (gcloud at --v=9, aws-iam-
	// authenticator with debug, etc.) can flood MBs into stderr; we'd
	// otherwise allocate a huge string, embed it in the error, and
	// dump the lot to the user's terminal — with raw ANSI escapes
	// leaking colour state and potentially mangling subsequent shell
	// output. capBytes + stripANSI keep the error message readable.
	var stderr bytes.Buffer
	cmd.Stderr = &cappedWriter{w: &stderr, limit: 8 << 10}
	out, err := cmd.Output()
	if err != nil {
		msg := strings.TrimSpace(stripANSI(stderr.String()))
		msg = capBytes(msg, 4096)
		if msg == "" {
			return fmt.Errorf("kubectl config view --merge: %w", err)
		}
		return fmt.Errorf("kubectl config view --merge: %w: %s", err, msg)
	}
	return writeFileAtomic(userPath, out, 0o600)
}

// cappedWriter wraps another io.Writer and silently drops bytes past
// `limit`. Used to bound the buffer a chatty subprocess can grow.
type cappedWriter struct {
	w     *bytes.Buffer
	limit int
}

func (c *cappedWriter) Write(p []byte) (int, error) {
	if c.w.Len() >= c.limit {
		return len(p), nil
	}
	remaining := c.limit - c.w.Len()
	if len(p) > remaining {
		c.w.Write(p[:remaining])
		c.w.WriteString("… (stderr truncated)")
		return len(p), nil
	}
	return c.w.Write(p)
}
