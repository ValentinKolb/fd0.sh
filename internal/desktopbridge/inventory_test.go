package desktopbridge

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/valentinkolb/fd0.sh/internal/cli"
	"github.com/valentinkolb/fd0.sh/internal/passitem"
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

func TestPassSearchMetadataIncludesUsefulLabelsWithoutSecrets(t *testing.T) {
	username, err := passitem.NewStringField(passitem.FieldText, "valentin@example.com")
	if err != nil {
		t.Fatal(err)
	}
	username.Name = "username"
	password, err := passitem.NewStringField(passitem.FieldSecret, "do-not-index-password")
	if err != nil {
		t.Fatal(err)
	}
	password.Name = "password"
	totp, err := passitem.NewTOTPField(passitem.TOTPValue{
		Secret:  "JBSWY3DPEHPK3PXP",
		Issuer:  "Example Inc",
		Account: "valentin@example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	totp.Name = "one-time code"
	file, err := passitem.NewFileField("recovery.txt", "text/plain", []byte("do-not-index-file"))
	if err != nil {
		t.Fatal(err)
	}
	file.Name = "recovery file"
	notes, err := passitem.NewStringField(passitem.FieldText, "do-not-index-notes")
	if err != nil {
		t.Fatal(err)
	}
	notes.Name = passitem.NotesFieldName

	search, hasTOTP := passSearchMetadata(&passitem.Item{
		Title:  "Example login",
		URLs:   []string{"https://example.com/sign-in"},
		Fields: []passitem.Field{username, password, totp, file, notes},
	})
	if !hasTOTP {
		t.Fatal("TOTP presence was not projected")
	}
	for _, want := range []string{
		"Example login", "example.com/sign-in", "username", "valentin@example.com",
		"Example Inc", "one-time code", "recovery.txt",
	} {
		if !strings.Contains(search, want) {
			t.Fatalf("search metadata %q does not contain %q", search, want)
		}
	}
	for _, secret := range []string{
		"do-not-index-password", "JBSWY3DPEHPK3PXP", "do-not-index-file", "do-not-index-notes",
	} {
		if strings.Contains(search, secret) {
			t.Fatalf("search metadata leaked %q: %q", secret, search)
		}
	}
}

// TestDetailFieldsProjectsCLINotes pins the seam between the CLI and the
// desktop: a note the CLI wrote through passitem.SetNotes must arrive in the
// detail view as the dedicated Notes field, exactly once, and must never also
// appear as an ordinary credential row.
func TestDetailFieldsProjectsCLINotes(t *testing.T) {
	newRecord := func(t *testing.T, item *passitem.Item) cli.TypedRecord {
		t.Helper()
		raw, err := json.Marshal(item)
		if err != nil {
			t.Fatal(err)
		}
		return cli.TypedRecord{Type: passitem.TypePassItem, Payload: string(raw)}
	}
	notesViews := func(views []FieldView) []FieldView {
		found := make([]FieldView, 0, 1)
		for _, view := range views {
			if view.Type == "notes" {
				found = append(found, view)
			}
		}
		return found
	}

	t.Run("a top-level note becomes the Notes field", func(t *testing.T) {
		item := &passitem.Item{Title: "GitHub"}
		if err := item.SetField("password", passitem.Field{Type: passitem.FieldSecret, Value: []byte(`"hunter2"`)}); err != nil {
			t.Fatal(err)
		}
		if err := item.SetNotes("Konsole nur über VPN."); err != nil {
			t.Fatal(err)
		}
		views, err := detailFields(newRecord(t, item), false)
		if err != nil {
			t.Fatal(err)
		}
		notes := notesViews(views)
		if len(notes) != 1 {
			t.Fatalf("want exactly one notes view, got %d (%+v)", len(notes), views)
		}
		if notes[0].Value != "Konsole nur über VPN." {
			t.Fatalf("notes value: got %q", notes[0].Value)
		}
		if notes[0].Sensitive {
			t.Fatal("the note is not a credential and must not be masked")
		}
		// It must not also survive as an ordinary row.
		for _, view := range views {
			if view.Type != "notes" && strings.EqualFold(view.Path, passitem.NotesFieldName) {
				t.Fatalf("the reserved note leaked into the field list: %+v", view)
			}
		}
		if views[len(views)-1].Type != "notes" {
			t.Fatal("the note must render last, as a footnote")
		}
	})

	t.Run("a note inside a section stays an ordinary field", func(t *testing.T) {
		item, err := passitem.Decode([]byte(`{"title":"Server","fields":[
			{"type":"section","name":"Recovery","fields":[
				{"type":"text","name":"notes","value":"gehört zum Abschnitt"}]}]}`))
		if err != nil {
			t.Fatal(err)
		}
		views, err := detailFields(newRecord(t, item), false)
		if err != nil {
			t.Fatal(err)
		}
		if got := notesViews(views); len(got) != 0 {
			t.Fatalf("a nested note must not be claimed as the item's note, got %+v", got)
		}
		if len(views) == 0 {
			t.Fatal("the nested field must still be rendered somewhere")
		}
	})
}

// TestDetailFieldsSurfacesEveryURL guards against the regression where only the
// first website was projected: the editor can add rows and the vault stores them
// all, so hiding the rest made them look lost.
func TestDetailFieldsSurfacesEveryURL(t *testing.T) {
	item := &passitem.Item{
		Title: "GitHub",
		URLs:  []string{"https://github.com", "https://gist.github.com"},
	}
	raw, err := json.Marshal(item)
	if err != nil {
		t.Fatal(err)
	}
	views, err := detailFields(cli.TypedRecord{Type: passitem.TypePassItem, Payload: string(raw)}, false)
	if err != nil {
		t.Fatal(err)
	}
	urls := make([]FieldView, 0, 2)
	for _, view := range views {
		if view.Type == "url" {
			urls = append(urls, view)
		}
	}
	if len(urls) != 2 {
		t.Fatalf("want both websites projected, got %d: %+v", len(urls), urls)
	}
	// The first must keep the bare path it has always had.
	if urls[0].Path != "$url" || urls[0].Value != "https://github.com" {
		t.Fatalf("first website: got path %q value %q", urls[0].Path, urls[0].Value)
	}
	if urls[1].Path != "$url:1" || urls[1].Value != "https://gist.github.com" {
		t.Fatalf("second website: got path %q value %q", urls[1].Path, urls[1].Value)
	}
	if urls[0].Name == urls[1].Name {
		t.Fatal("the alternative website needs a distinguishable name")
	}
}

func TestURLPathRoundTrip(t *testing.T) {
	for index := 0; index < 4; index++ {
		got, ok := urlIndex(urlPath(index))
		if !ok || got != index {
			t.Fatalf("index %d round trip: got %d ok=%v", index, got, ok)
		}
	}
	// Anything that merely looks like a URL path must not be claimed, or an
	// ordinary field of that name would resolve to a website.
	for _, path := range []string{"username", "$urls", "$url:", "$url:x", "$url:0", "$url:-1", "$urlx"} {
		if _, ok := urlIndex(path); ok {
			t.Fatalf("%q must not be treated as a URL path", path)
		}
	}
}
