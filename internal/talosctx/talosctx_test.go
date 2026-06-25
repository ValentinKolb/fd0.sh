package talosctx

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

const sampleTalosconfigYAML = `context: prod-1
contexts:
  prod-1:
    endpoints:
      - 10.0.1.10
      - 10.0.1.11
    nodes:
      - 10.0.1.10
    ca: QUFB
    crt: QkJC
    key: Q0ND
  staging:
    endpoints: ["192.168.1.50"]
    ca: RERE
    crt: RUVF
    key: RkZG
`

func TestParseTalosconfig(t *testing.T) {
	active, ctxs, err := ParseTalosconfig([]byte(sampleTalosconfigYAML))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if active != "prod-1" {
		t.Errorf("active: got %q want %q", active, "prod-1")
	}
	if len(ctxs) != 2 {
		t.Fatalf("contexts: got %d want 2", len(ctxs))
	}
	if ctxs[0].Name != "prod-1" || ctxs[0].CA != "QUFB" {
		t.Errorf("prod-1 wrong: %+v", ctxs[0])
	}
	if ctxs[1].Name != "staging" || ctxs[1].CA != "RERE" {
		t.Errorf("staging wrong: %+v", ctxs[1])
	}
}

func TestMarshalRoundTrip(t *testing.T) {
	orig := &TalosContext{
		Name:      "prod-1",
		Endpoints: []string{"10.0.1.10"},
		Nodes:     []string{"10.0.1.10"},
		CA:        b64("AAA"),
		Crt:       b64("BBB"),
		Key:       b64("CCC"),
		Role:      RoleOperator,
		Tags:      []string{"prod"},
	}
	bs, err := json.Marshal(orig.Marshal())
	if err != nil {
		t.Fatalf("json: %v", err)
	}
	rt, err := Unmarshal(bs)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if rt.Name != orig.Name || rt.CA != orig.CA || rt.Role != orig.Role {
		t.Errorf("round-trip drifted: %+v vs %+v", orig, rt)
	}
}

func TestValidate(t *testing.T) {
	good := &TalosContext{
		Name:      "ok",
		Endpoints: []string{"1.2.3.4"},
		CA:        b64("ca"),
		Crt:       b64("crt"),
		Key:       b64("key"),
	}
	if err := good.Validate(); err != nil {
		t.Fatalf("good: %v", err)
	}

	bad := []*TalosContext{
		// alias regex
		{Name: "0bad-start"},
		// no endpoints
		{Name: "ok"},
		// no ca
		{Name: "ok", Endpoints: []string{"x"}},
		// bad base64
		{Name: "ok", Endpoints: []string{"x"}, CA: "not-base64!"},
		// no crt/key
		{Name: "ok", Endpoints: []string{"x"}, CA: b64("a")},
		// bad role
		{Name: "ok", Endpoints: []string{"x"}, CA: b64("a"), Crt: b64("b"), Key: b64("c"), Role: "garbage"},
	}
	for i, c := range bad {
		if err := c.Validate(); err == nil {
			t.Errorf("case %d: expected error, got none for %+v", i, c)
		}
	}
}

func TestSortContexts(t *testing.T) {
	cc := []*TalosContext{
		{Name: "b", Scope: "work"},
		{Name: "a", Scope: "work"},
		{Name: "c", Scope: "personal"},
	}
	SortContexts(cc)
	want := []string{"c", "a", "b"} // personal < work, then alpha
	for i, c := range cc {
		if c.Name != want[i] {
			t.Errorf("pos %d: got %q want %q", i, c.Name, want[i])
		}
	}
}

func TestRenderDeterministic(t *testing.T) {
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	in := RenderInput{
		ActiveContext: "prod-1",
		Now:           now,
		Contexts: []*TalosContext{
			{
				Name: "prod-1", Scope: "work",
				Endpoints: []string{"10.0.1.10"},
				Nodes:     []string{"10.0.1.10"},
				CA:        b64("ca"), Crt: b64("crt"), Key: b64("key"),
				Role: RoleAdmin,
			},
		},
	}
	a, _ := Render(in)
	b, _ := Render(in)
	if string(a) != string(b) {
		t.Fatal("render not deterministic")
	}
	if !strings.Contains(string(a), "context: prod-1") {
		t.Error("active context missing")
	}
	if !strings.Contains(string(a), "fd0 — managed talosconfig") {
		t.Error("header missing")
	}
}

func TestRenderSingleContextBecomesActive(t *testing.T) {
	in := RenderInput{
		Now: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
		Contexts: []*TalosContext{
			{
				Name: "prod-1", Scope: "work",
				Endpoints: []string{"10.0.1.10"},
				CA:        b64("ca"), Crt: b64("crt"), Key: b64("key"),
			},
		},
	}
	out, _ := Render(in)
	if !strings.Contains(string(out), "context: prod-1") {
		t.Fatalf("single rendered context should become active:\n%s", out)
	}
}

func TestRenderCrossScopeCollisionWarning(t *testing.T) {
	in := RenderInput{
		Now: time.Now(),
		Contexts: []*TalosContext{
			{
				Name: "shared", Scope: "personal",
				Endpoints: []string{"1.1.1.1"},
				CA:        b64("a"), Crt: b64("b"), Key: b64("c"),
			},
			{
				Name: "shared", Scope: "work",
				Endpoints: []string{"2.2.2.2"},
				CA:        b64("a"), Crt: b64("b"), Key: b64("c"),
			},
		},
	}
	out, warnings := Render(in)
	if len(warnings) != 1 {
		t.Errorf("warnings: got %d want 1", len(warnings))
	}
	if !strings.Contains(string(out), "WARNINGS:") {
		t.Error("warning block missing in rendered header")
	}
	if !strings.Contains(string(out), "1.1.1.1") {
		t.Error("first-by-sort (personal scope) should be the one emitted")
	}
	if strings.Contains(string(out), "2.2.2.2") {
		t.Error("collision: work-scope should have been suppressed")
	}
}

func TestSplitEndpoints(t *testing.T) {
	got := SplitEndpoints([]string{"a,b", "c", " d ,e"})
	want := []string{"a", "b", "c", "d", "e"}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("pos %d: got %q want %q", i, got[i], want[i])
		}
	}
}

func b64(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}
