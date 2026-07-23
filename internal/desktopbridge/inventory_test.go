package desktopbridge

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestInventoryBoundsUntrustedMetadata(t *testing.T) {
	long := strings.Repeat("x", maxInventoryTextRunes+100)
	summary := boundItemSummary(ItemSummary{
		Title:     long,
		Subtitle:  "line\nbreak",
		Vault:     long,
		Badge:     long,
		UpdatedAt: long,
	})
	for name, value := range map[string]string{
		"title": summary.Title, "vault": summary.Vault, "badge": summary.Badge, "updated": summary.UpdatedAt,
	} {
		if utf8.RuneCountInString(value) != maxInventoryTextRunes {
			t.Fatalf("%s runes=%d", name, utf8.RuneCountInString(value))
		}
	}
	if summary.Subtitle != "line break" {
		t.Fatalf("control character was not neutralized: %q", summary.Subtitle)
	}
	if !safeInventoryRecordName("pass:github") {
		t.Fatal("ordinary record name rejected")
	}
	for _, name := range []string{
		"",
		"line\nbreak",
		strings.Repeat("x", maxInventoryRecordName+1),
	} {
		if safeInventoryRecordName(name) {
			t.Fatalf("unsafe record name accepted: %q", name)
		}
	}
}
