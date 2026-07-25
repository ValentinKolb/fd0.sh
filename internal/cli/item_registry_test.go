package cli

import (
	"strings"
	"testing"
)

// TestItemKindsAreConsistent is the guard that keeps the modules uniform.
//
// Every shared behaviour — move, rename, the duplicate message, the edit hint —
// reads the same registry. A new module that forgets an entry, reuses a prefix,
// or names itself after a command that does not exist would silently behave
// differently from the rest; this fails instead.
func TestItemKindsAreConsistent(t *testing.T) {
	seenPrefix := map[string]string{}
	seenCommand := map[string]string{}

	for _, kind := range itemKinds {
		if kind.Noun == "" {
			t.Errorf("kind with prefix %q has no noun; it would produce messages like `moved  \"x\"`", kind.Prefix)
		}
		if kind.Command == "" {
			t.Errorf("kind %q has no command; recovery hints would name `fd0  rm ...`", kind.Noun)
		}
		if other, ok := seenCommand[kind.Command]; ok {
			t.Errorf("kinds %q and %q share the command %q", other, kind.Noun, kind.Command)
		}
		seenCommand[kind.Command] = kind.Noun

		// The secret kind deliberately has no prefix: its records are the
		// bare names users typed. Every other kind must be distinguishable.
		if kind.Prefix == "" {
			if kind.Noun != "secret" {
				t.Errorf("kind %q has no prefix; only plain secrets may be unprefixed", kind.Noun)
			}
			continue
		}
		if !strings.HasSuffix(kind.Prefix, ":") {
			t.Errorf("kind %q prefix %q must end in %q so names cannot collide across kinds",
				kind.Noun, kind.Prefix, ":")
		}
		if other, ok := seenPrefix[kind.Prefix]; ok {
			t.Errorf("kinds %q and %q share the record prefix %q — one would read the other's records",
				other, kind.Noun, kind.Prefix)
		}
		seenPrefix[kind.Prefix] = kind.Noun
	}
}

// TestEditHintCoversEveryKind pins the promise the duplicate error makes: if it
// tells the user to run `fd0 X edit`, every prefixed kind must produce one.
func TestEditHintCoversEveryKind(t *testing.T) {
	for _, kind := range itemKinds {
		if kind.Prefix == "" {
			continue
		}
		hint := editHint(kind.Prefix, "example")
		if !strings.Contains(hint, "fd0 "+kind.Command+" edit example") {
			t.Errorf("kind %q: edit hint %q does not name its own edit command", kind.Noun, hint)
		}
		if warning := forceWarning(kind.Prefix, "example"); !strings.Contains(warning, kind.Command) {
			t.Errorf("kind %q: force warning %q does not name its own module", kind.Noun, warning)
		}
	}
	// An unknown prefix must degrade to no advice rather than to wrong advice.
	if hint := editHint("nosuch:", "example"); hint != "" {
		t.Errorf("unknown prefix produced advice: %q", hint)
	}
}

func TestValidItemName(t *testing.T) {
	valid := []string{"prod-db", "a", "host.example.com", "with space", "ümlaut"}
	for _, name := range valid {
		if err := validItemName(name); err != nil {
			t.Errorf("validItemName(%q) = %v, want nil", name, err)
		}
	}
	// A colon would let a rename forge a record of another kind, e.g. renaming
	// a pass item to "host:prod" so it lands among the SSH hosts.
	invalid := []string{"", "   ", " leading", "trailing ", "host:prod", "with\nnewline", "with\ttab"}
	for _, name := range invalid {
		if err := validItemName(name); err == nil {
			t.Errorf("validItemName(%q) = nil, want an error", name)
		}
	}
}
