package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func TestPassBrowserDetailQQuits(t *testing.T) {
	m := newPassBrowserModel([]PassBrowserItem{{
		ID:    "1",
		Title: "github",
		Scope: "work",
	}}, "")
	m.mode = passBrowserDetail

	next, _ := m.updateDetail(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("q")})
	got := next.(*passBrowserModel)
	if !got.cancelled {
		t.Fatal("q should cancel the pass detail view")
	}
}

func TestPassBrowserListQQuitsWhenSearchIsEmpty(t *testing.T) {
	m := newPassBrowserModel([]PassBrowserItem{{
		ID:    "1",
		Title: "github",
		Scope: "work",
	}}, "")

	next, _ := m.updateList(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("q")})
	got := next.(*passBrowserModel)
	if !got.cancelled {
		t.Fatal("q should cancel the pass list view when search is empty")
	}
}

func TestPassBrowserListQExtendsNonEmptySearch(t *testing.T) {
	m := newPassBrowserModel([]PassBrowserItem{{
		ID:     "1",
		Title:  "github",
		Scope:  "work",
		Search: "github",
	}}, "g")

	next, _ := m.updateList(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("q")})
	got := next.(*passBrowserModel)
	if got.cancelled {
		t.Fatal("q should remain searchable once a query is active")
	}
	if got.query != "gq" {
		t.Fatalf("query = %q, want gq", got.query)
	}
}

func TestPassBrowserDetailFooterMentionsQ(t *testing.T) {
	m := newPassBrowserModel([]PassBrowserItem{{
		ID:    "1",
		Title: "github",
		Scope: "work",
	}}, "")
	m.mode = passBrowserDetail

	if got := m.View(); !strings.Contains(got, "q quit") {
		t.Fatalf("detail footer does not mention q quit:\n%s", got)
	}
}
