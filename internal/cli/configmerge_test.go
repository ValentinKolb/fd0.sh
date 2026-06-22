package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// The merge must preserve the user's existing entries that fd0 doesn't
// model — most importantly kubeconfig exec / auth-provider auth used by
// EKS / GKE. A naive parse-via-typed-codec + re-render would delete
// them; this test is the guard against that regression.
func TestMergeKubeconfigPreservesExecAuth(t *testing.T) {
	dir := t.TempDir()
	userPath := filepath.Join(dir, "config")
	fd0Path := filepath.Join(dir, "config.fd0")

	// User already has an EKS cluster using exec auth + a stale fd0
	// entry "prod" that the new render will replace.
	userYAML := `apiVersion: v1
kind: Config
current-context: eks-prod
clusters:
- name: eks-prod
  cluster:
    server: https://eks.example.com
    certificate-authority-data: RUtT
- name: prod
  cluster:
    server: https://old:6443
    certificate-authority-data: T0xE
users:
- name: eks-prod
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1beta1
      command: aws
      args: ["eks", "get-token", "--cluster-name", "prod"]
- name: prod
  user:
    client-certificate-data: T0xE
    client-key-data: T0xF
contexts:
- name: eks-prod
  context:
    cluster: eks-prod
    user: eks-prod
- name: prod
  context:
    cluster: prod
    user: prod
`
	// fd0's freshly-rendered config: only its own "prod" cluster, with
	// a NEW server + cert.
	fd0YAML := `apiVersion: v1
kind: Config
clusters:
- name: prod
  cluster:
    server: https://new:6443
    certificate-authority-data: TkVX
users:
- name: prod
  user:
    client-certificate-data: TkVX
    client-key-data: TkVZ
contexts:
- name: prod
  context:
    cluster: prod
    user: prod
`
	if err := os.WriteFile(userPath, []byte(userYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fd0Path, []byte(fd0YAML), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := mergeKubeconfigFile(fd0Path, userPath); err != nil {
		t.Fatalf("merge: %v", err)
	}

	merged, _ := os.ReadFile(userPath)
	var doc map[string]any
	if err := yaml.Unmarshal(merged, &doc); err != nil {
		t.Fatalf("merged not valid YAML: %v", err)
	}

	s := string(merged)
	// 1. The user's EKS exec-auth cluster survived (re-marshalled YAML
	// may put the exec args on their own lines, so check tokens, not a
	// space-joined string).
	if !strings.Contains(s, "eks.example.com") ||
		!strings.Contains(s, "command: aws") ||
		!strings.Contains(s, "get-token") {
		t.Errorf("EKS exec-auth cluster was dropped:\n%s", s)
	}
	// 2. fd0's "prod" replaced the stale one (new server, not old).
	if !strings.Contains(s, "https://new:6443") {
		t.Errorf("fd0 prod cluster not merged in:\n%s", s)
	}
	if strings.Contains(s, "https://old:6443") {
		t.Errorf("stale prod cluster not replaced:\n%s", s)
	}
	// 3. No duplicate "prod" cluster.
	clusters := asSlice(doc["clusters"])
	n := 0
	for _, c := range clusters {
		if m, ok := c.(map[string]any); ok && m["name"] == "prod" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("expected exactly one prod cluster, got %d", n)
	}
	// 4. current-context untouched.
	if doc["current-context"] != "eks-prod" {
		t.Errorf("current-context changed: %v", doc["current-context"])
	}
}

func TestMergeKubeconfigCreatesWhenMissing(t *testing.T) {
	dir := t.TempDir()
	userPath := filepath.Join(dir, "config") // does not exist
	fd0Path := filepath.Join(dir, "config.fd0")
	fd0YAML := `apiVersion: v1
kind: Config
clusters:
- name: prod
  cluster: {server: "https://x:6443", certificate-authority-data: "QQ=="}
users:
- name: prod
  user: {token: "t"}
contexts:
- name: prod
  context: {cluster: prod, user: prod}
`
	if err := os.WriteFile(fd0Path, []byte(fd0YAML), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := mergeKubeconfigFile(fd0Path, userPath); err != nil {
		t.Fatalf("merge into missing file: %v", err)
	}
	out, err := os.ReadFile(userPath)
	if err != nil {
		t.Fatalf("user file not created: %v", err)
	}
	if !strings.Contains(string(out), "name: prod") {
		t.Errorf("fd0 cluster missing from fresh file:\n%s", out)
	}
}

func TestMergeTalosconfigPreservesForeignContext(t *testing.T) {
	dir := t.TempDir()
	userPath := filepath.Join(dir, "config")
	fd0Path := filepath.Join(dir, "config.fd0")

	userYAML := `context: hand-rolled
contexts:
  hand-rolled:
    endpoints: ["10.9.9.9"]
    ca: SAND
    crt: SANE
    key: SANF
  prod:
    endpoints: ["10.0.0.1"]
    ca: T0xE
    crt: T0xF
    key: T0xG
`
	fd0YAML := `contexts:
  prod:
    endpoints: ["10.0.0.99"]
    ca: TkVX
    crt: TkVZ
    key: TkVa
`
	if err := os.WriteFile(userPath, []byte(userYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fd0Path, []byte(fd0YAML), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := mergeTalosconfigFile(fd0Path, userPath); err != nil {
		t.Fatalf("merge: %v", err)
	}
	merged, _ := os.ReadFile(userPath)
	var doc map[string]any
	if err := yaml.Unmarshal(merged, &doc); err != nil {
		t.Fatalf("merged not valid YAML: %v", err)
	}
	ctxs := asStringMap(doc["contexts"])
	if _, ok := ctxs["hand-rolled"]; !ok {
		t.Errorf("foreign context dropped:\n%s", merged)
	}
	// fd0's prod overwrote the stale endpoint.
	if !strings.Contains(string(merged), "10.0.0.99") {
		t.Errorf("fd0 prod not merged in:\n%s", merged)
	}
	if strings.Contains(string(merged), "10.0.0.1\n") {
		t.Errorf("stale prod endpoint not replaced:\n%s", merged)
	}
	// User's active context preserved (not overwritten by fd0).
	if doc["context"] != "hand-rolled" {
		t.Errorf("active context changed: %v", doc["context"])
	}
}
