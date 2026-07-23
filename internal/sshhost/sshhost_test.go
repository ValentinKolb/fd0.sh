package sshhost

import (
	"strings"
	"testing"
	"time"
)

func TestParseConnString(t *testing.T) {
	cases := []struct {
		in       string
		wantUser string
		wantHost string
		wantPort int
	}{
		{"", "", "", 0},
		{"host", "", "host", 0},
		{"user@host", "user", "host", 0},
		{"host:22", "", "host", 22},
		{"user@host:2222", "user", "host", 2222},
		{"app@db.internal.example.com", "app", "db.internal.example.com", 0},
		{"user@host.example.com:42", "user", "host.example.com", 42},
	}
	for _, c := range cases {
		u, h, p, err := ParseConnString(c.in)
		if err != nil {
			t.Errorf("%q: %v", c.in, err)
			continue
		}
		if u != c.wantUser || h != c.wantHost || p != c.wantPort {
			t.Errorf("%q → (%q,%q,%d) want (%q,%q,%d)",
				c.in, u, h, p, c.wantUser, c.wantHost, c.wantPort)
		}
	}
}

func TestValidate(t *testing.T) {
	good := []*Host{
		{Alias: "prod-db", Hostname: "db", Port: 22},
		{Alias: "Bastion", Hostname: "bastion.example.com"},
		{Alias: "h_1", Hostname: "10.0.0.1"},
	}
	for _, h := range good {
		if err := h.Validate(); err != nil {
			t.Errorf("%q should be valid: %v", h.Alias, err)
		}
	}
	bad := []*Host{
		{Alias: "", Hostname: "h"},                                             // empty alias
		{Alias: "has space", Hostname: "h"},                                    // whitespace
		{Alias: "host", Hostname: ""},                                          // empty hostname
		{Alias: "host", Hostname: "h", Port: 99999},                            // bad port
		{Alias: "host", Hostname: "h", Options: map[string]string{"K V": "x"}}, // option key whitespace
		// S1: injection guards on render-verbatim fields.
		{Alias: "host", Hostname: "x\n    ProxyCommand sh -c id"},            // newline in hostname
		{Alias: "host", Hostname: "x\r\nProxyCommand x"},                     // CRLF in hostname
		{Alias: "host", Hostname: "x", User: "root\nProxyCommand x"},         // newline in user
		{Alias: "host", Hostname: "x", ProxyJump: "bastion\nProxyCommand x"}, // newline in proxy-jump
		{Alias: "host", Hostname: "host\x00wat"},                             // NUL in hostname
		{Alias: "host", Hostname: "host\twat"},                               // tab in hostname
	}
	for _, h := range bad {
		if err := h.Validate(); err == nil {
			t.Errorf("%+v should be invalid", h)
		}
	}
}

func TestRoundTrip(t *testing.T) {
	orig := &Host{
		Alias:       "prod-db",
		Hostname:    "db.internal",
		User:        "app",
		Port:        2222,
		KeyName:     "deploy",
		ProxyJump:   "bastion",
		Tags:        []string{"prod", "db"},
		Description: "Production DB main",
		Options:     map[string]string{"ServerAliveInterval": "30"},
		Scope:       "work",
	}
	j := orig.Marshal()
	if j.Type != TypeHost {
		t.Fatalf("Type=%s", j.Type)
	}
	got, err := Unmarshal(j)
	if err != nil {
		t.Fatal(err)
	}
	// Scope is intentionally not in the JSON value.
	got.Scope = orig.Scope
	if got.Alias != orig.Alias ||
		got.Hostname != orig.Hostname ||
		got.User != orig.User ||
		got.Port != orig.Port ||
		got.KeyName != orig.KeyName ||
		got.ProxyJump != orig.ProxyJump ||
		got.Description != orig.Description ||
		len(got.Tags) != len(orig.Tags) ||
		len(got.Options) != len(orig.Options) {
		t.Fatalf("round-trip drift:\n  orig=%+v\n  got =%+v", orig, got)
	}
}

func TestSharedOptionsPolicy(t *testing.T) {
	got, err := SharedOptions(map[string]string{
		"serveraliveinterval": "30",
		"Compression":         "yes",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 ||
		got[0] != (Option{Name: "Compression", Value: "yes"}) ||
		got[1] != (Option{Name: "ServerAliveInterval", Value: "30"}) {
		t.Fatalf("unexpected canonical options: %+v", got)
	}

	for _, name := range []string{
		"ProxyCommand",
		"proxycommand",
		"LocalCommand",
		"PermitLocalCommand",
		"KnownHostsCommand",
		"Match",
		"ForwardAgent",
		"IdentityAgent",
		"IdentityFile",
		"Include",
		"RemoteCommand",
		"PKCS11Provider",
		"LocalForward",
		"RemoteForward",
		"DynamicForward",
		"ControlPath",
		"XAuthLocation",
		"UnknownOption",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := SharedOptions(map[string]string{name: "value"})
			if err == nil {
				t.Fatalf("%s should not be allowed in synchronized hosts", name)
			}
			if !strings.Contains(err.Error(), "configure it locally") {
				t.Fatalf("error should explain the local-only path: %v", err)
			}
		})
	}

	if _, err := SharedOptions(map[string]string{
		"Compression": "yes",
		"compression": "no",
	}); err == nil {
		t.Fatal("case-insensitive duplicate should be rejected")
	}
}

func TestRenderBasic(t *testing.T) {
	hosts := []*Host{
		{Alias: "bastion", Hostname: "bastion.example.com", User: "ops", Scope: "work", Tags: []string{"prod"}},
		{Alias: "prod-db", Hostname: "db.internal", User: "app", KeyName: "deploy", ProxyJump: "bastion",
			Scope: "work", Tags: []string{"prod", "db"}, Description: "Main DB"},
		{Alias: "personal-vps", Hostname: "vps.example.com", Scope: "personal"},
	}
	out := mustRender(t, RenderInput{
		Hosts:      hosts,
		SocketPath: "/tmp/fd0/ssh.sock",
		KnownKeys:  map[string]bool{"deploy": true},
		PubKeyDir:  "/tmp/fd0/pub",
		Now:        time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC),
	})
	s := string(out)
	for _, want := range []string{
		"# Managed by fd0",
		"# Generated: 2026-06-08T12:00:00Z",
		"# ─── scope: personal ",
		"# ─── scope: work ",
		"Host bastion\n",
		"Host prod-db\n",
		"Host personal-vps\n",
		"HostName db.internal",
		"User app",
		"ProxyJump bastion",
		"IdentityAgent /tmp/fd0/ssh.sock",
		// prod-db has a resolvable key → selector file + IdentitiesOnly.
		"IdentityFile /tmp/fd0/pub/prod-db.pub",
		"IdentitiesOnly yes",
		"#@fd0:scope=work",
		"#@fd0:tags=prod,db",
		"#@fd0:desc=Main DB",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("output missing %q\n--- output ---\n%s", want, s)
		}
	}
	// personal scope should come BEFORE work scope (alphabetical).
	pi := strings.Index(s, "# ─── scope: personal")
	wi := strings.Index(s, "# ─── scope: work")
	if pi < 0 || wi < 0 || !(pi < wi) {
		t.Errorf("scopes not in alphabetical order (personal=%d, work=%d)", pi, wi)
	}
}

func TestRenderDeterministic(t *testing.T) {
	// Same input → same output, regardless of map iteration order.
	hosts := []*Host{
		{Alias: "h", Hostname: "x", Scope: "s",
			Options: map[string]string{
				"ServerAliveInterval": "30",
				"Compression":         "yes",
				"ConnectTimeout":      "10",
			}},
	}
	now := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	a := string(mustRender(t, RenderInput{Hosts: hosts, Now: now}))
	for i := 0; i < 5; i++ {
		b := string(mustRender(t, RenderInput{Hosts: hosts, Now: now}))
		if a != b {
			t.Fatalf("non-deterministic render:\n--- a ---\n%s\n--- b ---\n%s", a, b)
		}
	}
}

func TestRenderKeyedHostEmitsIdentityFile(t *testing.T) {
	hosts := []*Host{
		{Alias: "prod-db", Hostname: "db", KeyName: "deploy", Scope: "work"},
	}
	out := string(mustRender(t, RenderInput{
		Hosts:      hosts,
		SocketPath: "/run/fd0.sock",
		KnownKeys:  map[string]bool{"deploy": true},
		PubKeyDir:  "/home/me/.ssh/fd0.d",
		Now:        time.Now(),
	}))
	if !strings.Contains(out, "IdentityFile /home/me/.ssh/fd0.d/prod-db.pub") {
		t.Errorf("keyed host should emit IdentityFile:\n%s", out)
	}
	if !strings.Contains(out, "IdentitiesOnly yes") {
		t.Errorf("keyed host should emit IdentitiesOnly:\n%s", out)
	}
}

func TestRenderKeylessHostNoIdentitiesOnly(t *testing.T) {
	// A host without an fd0 key must NOT get IdentitiesOnly — that
	// would suppress the user's own ~/.ssh identities too.
	hosts := []*Host{
		{Alias: "byok", Hostname: "h", Scope: "s"},
	}
	out := string(mustRender(t, RenderInput{
		Hosts:      hosts,
		SocketPath: "/run/fd0.sock",
		PubKeyDir:  "/home/me/.ssh/fd0.d",
		Now:        time.Now(),
	}))
	if !strings.Contains(out, "IdentityAgent /run/fd0.sock") {
		t.Errorf("keyless host should still get IdentityAgent:\n%s", out)
	}
	if strings.Contains(out, "IdentitiesOnly") {
		t.Errorf("keyless host must NOT get IdentitiesOnly:\n%s", out)
	}
	if strings.Contains(out, "IdentityFile") {
		t.Errorf("keyless host must NOT get IdentityFile:\n%s", out)
	}
}

func TestRenderMissingKeyWarning(t *testing.T) {
	hosts := []*Host{
		{Alias: "h", Hostname: "x", KeyName: "ghost", Scope: "s"},
	}
	out := mustRender(t, RenderInput{
		Hosts:     hosts,
		KnownKeys: map[string]bool{"deploy": true}, // ghost not in set
		Now:       time.Now(),
	})
	if !strings.Contains(string(out), `# WARN: host "h" references missing key "ghost"`) {
		t.Errorf("missing key warning not emitted:\n%s", string(out))
	}
}

func TestRenderCrossScopeCollision(t *testing.T) {
	hosts := []*Host{
		{Alias: "prod-db", Hostname: "db.a", Scope: "work"},
		{Alias: "prod-db", Hostname: "db.b", Scope: "old-work"},
	}
	out := string(mustRender(t, RenderInput{Hosts: hosts, Now: time.Now()}))
	if !strings.Contains(out, "alias collisions across scopes") {
		t.Fatalf("collision warning missing:\n%s", out)
	}
	// First in alphabetical scope order (old-work) wins.
	if !strings.Contains(out, `alias "prod-db" defined in scopes [old-work, work] — "old-work" wins`) {
		t.Errorf("collision detail wrong:\n%s", out)
	}
	// Only the winning entry should appear as Host block.
	if strings.Count(out, "Host prod-db\n") != 1 {
		t.Errorf("expected one Host prod-db block:\n%s", out)
	}
	if !strings.Contains(out, "HostName db.b") {
		t.Errorf("expected HostName db.b (from old-work, first by sort):\n%s", out)
	}
}

func TestRenderRejectsUnvalidatedSharedOptions(t *testing.T) {
	_, err := Render(RenderInput{
		Hosts: []*Host{{
			Alias:    "prod",
			Hostname: "prod.example.com",
			Scope:    "work",
			Options:  map[string]string{"ProxyCommand": "sh -c id"},
		}},
		Now: time.Now(),
	})
	if err == nil {
		t.Fatal("renderer must reject unsafe options even when the caller skipped validation")
	}
	if !strings.Contains(err.Error(), "ProxyCommand") {
		t.Fatalf("error should identify the rejected option: %v", err)
	}
}

func mustRender(t *testing.T, in RenderInput) []byte {
	t.Helper()
	out, err := Render(in)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
