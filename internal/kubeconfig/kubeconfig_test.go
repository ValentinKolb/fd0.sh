package kubeconfig

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

const sampleKubeconfigYAML = `apiVersion: v1
kind: Config
current-context: prod
clusters:
- name: prod
  cluster:
    server: https://10.0.1.10:6443
    certificate-authority-data: QUFB
- name: staging
  cluster:
    server: https://192.168.1.50:6443
    insecure-skip-tls-verify: true
users:
- name: prod
  user:
    client-certificate-data: QkJC
    client-key-data: Q0ND
- name: staging
  user:
    token: bearer-xxx
- name: oidc-thing
  user:
    auth-provider:
      name: oidc
contexts:
- name: prod
  context:
    cluster: prod
    user: prod
    namespace: kube-system
- name: staging
  context:
    cluster: staging
    user: staging
- name: orphan
  context:
    cluster: missing
    user: prod
- name: oidc
  context:
    cluster: prod
    user: oidc-thing
`

func TestParseKubeconfig(t *testing.T) {
	active, kk, skipped, err := ParseKubeconfig([]byte(sampleKubeconfigYAML))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if active != "prod" {
		t.Errorf("active: got %q want prod", active)
	}
	if len(kk) != 2 {
		t.Fatalf("kk: got %d want 2", len(kk))
	}
	if kk[0].Name != "prod" || kk[0].Server != "https://10.0.1.10:6443" || kk[0].Namespace != "kube-system" {
		t.Errorf("prod parsed wrong: %+v", kk[0])
	}
	if kk[1].Name != "staging" || !kk[1].InsecureSkipTLSVerify || kk[1].Token != "bearer-xxx" {
		t.Errorf("staging parsed wrong: %+v", kk[1])
	}
	if len(skipped) != 2 {
		t.Errorf("skipped: got %d want 2 (orphan + oidc): %v", len(skipped), skipped)
	}
}

func TestMarshalRoundTrip(t *testing.T) {
	orig := &Kubeconfig{
		Name:       "prod",
		Server:     "https://10.0.1.10:6443",
		CA:         b64("ca"),
		ClientCert: b64("crt"),
		ClientKey:  b64("key"),
		Namespace:  "default",
		Tags:       []string{"prod"},
	}
	bs, _ := json.Marshal(orig.Marshal())
	rt, err := Unmarshal(bs)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if rt.Name != "prod" || rt.Server != orig.Server || rt.Namespace != "default" {
		t.Errorf("round-trip drifted: %+v", rt)
	}
}

func TestValidate(t *testing.T) {
	good := &Kubeconfig{
		Name: "ok", Server: "https://x", CA: b64("a"),
		ClientCert: b64("b"), ClientKey: b64("c"),
	}
	if err := good.Validate(); err != nil {
		t.Fatalf("good: %v", err)
	}

	bad := []*Kubeconfig{
		// alias regex (spaces forbidden)
		{Name: "bad name", Server: "https://x", CA: b64("a"), Token: "t"},
		// bad scheme
		{Name: "ok", Server: "ssh://x", CA: b64("a"), Token: "t"},
		// no CA, no skip, no auth
		{Name: "ok", Server: "https://x"},
		// bad ca
		{Name: "ok", Server: "https://x", CA: "not-base64!", Token: "t"},
		// no auth at all
		{Name: "ok", Server: "https://x", CA: b64("a")},
	}
	for i, k := range bad {
		if err := k.Validate(); err == nil {
			t.Errorf("case %d: expected error: %+v", i, k)
		}
	}
}

func TestRenderDeterministic(t *testing.T) {
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	in := RenderInput{
		CurrentContext: "prod",
		Now:            now,
		Configs: []*Kubeconfig{
			{
				Name: "prod", Scope: "work",
				Server: "https://10.0.1.10:6443",
				CA:     b64("ca"), ClientCert: b64("crt"), ClientKey: b64("key"),
			},
		},
	}
	a, _ := Render(in)
	b, _ := Render(in)
	if string(a) != string(b) {
		t.Fatal("not deterministic")
	}
	if !strings.Contains(string(a), "current-context: prod") {
		t.Error("current-context missing")
	}
	if !strings.Contains(string(a), "fd0 — managed kubeconfig") {
		t.Error("header missing")
	}
	// round-trip via the parser back
	_, kk, _, err := ParseKubeconfig(a)
	if err != nil {
		t.Fatalf("re-parse: %v", err)
	}
	if len(kk) != 1 || kk[0].Name != "prod" {
		t.Errorf("re-parse drifted: %+v", kk)
	}
}

func TestRenderSingleConfigBecomesCurrentContext(t *testing.T) {
	in := RenderInput{
		Now: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
		Configs: []*Kubeconfig{
			{
				Name: "prod", Scope: "work",
				Server: "https://10.0.1.10:6443",
				CA:     b64("ca"), ClientCert: b64("crt"), ClientKey: b64("key"),
			},
		},
	}
	out, _ := Render(in)
	if !strings.Contains(string(out), "current-context: prod") {
		t.Fatalf("single rendered kubeconfig should become current-context:\n%s", out)
	}
}

func TestRenderCrossScopeCollision(t *testing.T) {
	in := RenderInput{
		Now: time.Now(),
		Configs: []*Kubeconfig{
			{
				Name: "dup", Scope: "personal",
				Server: "https://1.1.1.1", CA: b64("a"),
				ClientCert: b64("b"), ClientKey: b64("c"),
			},
			{
				Name: "dup", Scope: "work",
				Server: "https://2.2.2.2", CA: b64("a"),
				ClientCert: b64("b"), ClientKey: b64("c"),
			},
		},
	}
	out, warnings := Render(in)
	if len(warnings) != 1 {
		t.Errorf("warnings: got %d want 1", len(warnings))
	}
	if strings.Contains(string(out), "2.2.2.2") {
		t.Error("work-scope dup should be suppressed")
	}
	if !strings.Contains(string(out), "1.1.1.1") {
		t.Error("personal-scope (first-by-sort) should win")
	}
}

func b64(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}
