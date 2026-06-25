package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func TestPickerQQuits(t *testing.T) {
	m := &pickerModel{
		items: []PickerItem{{ID: "1", Label: "one"}},
		width: 80,
	}

	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("q")})
	got := next.(*pickerModel)
	if !got.cancelled {
		t.Fatal("q should cancel picker")
	}
}

func TestPickerFooterMentionsQ(t *testing.T) {
	m := &pickerModel{
		items: []PickerItem{{ID: "1", Label: "one"}},
		width: 80,
	}

	if got := m.View(); !strings.Contains(got, "esc/q") {
		t.Fatalf("picker footer does not mention esc/q:\n%s", got)
	}
}
