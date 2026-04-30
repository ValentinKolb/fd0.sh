// Package tui implements fd0's inline interactive UI: a fuzzy-search secret
// browser. Renders inline (no alt-screen) so the final selection becomes part
// of the normal scrollback.
package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/sahilm/fuzzy"
)

// Entry is the minimal information the searcher needs about one secret.
type Entry struct {
	ScopeID    string
	ScopeLabel string // optional human-readable label
	ID         string
	Name       string
	Type       string
}

// Selection is what the TUI returns. Empty Name means cancelled.
type Selection struct {
	Entry Entry
	Final string // final-frame line shown after Quit
}

// Run shows the searcher with the given entries. Returns Selection.
func Run(entries []Entry) (Selection, error) {
	m := newModel(entries)
	p := tea.NewProgram(m, tea.WithOutput(stderr{}))
	final, err := p.Run()
	if err != nil {
		return Selection{}, err
	}
	mm := final.(*model)
	if mm.cancelled {
		return Selection{}, nil
	}
	return Selection{Entry: mm.selected(), Final: mm.finalLine()}, nil
}

// stderr lets bubbletea render to os.Stderr so stdout stays clean for
// machine-readable output (e.g. `fd0 get --raw | foo`).
type stderr struct{}

func (stderr) Write(p []byte) (int, error) {
	return _stderrWrite(p)
}

// ---- model ----

type model struct {
	all       []Entry
	matches   []match
	query     string
	cursor    int
	cancelled bool
	chosen    bool
	width     int // current terminal width; updated via WindowSizeMsg

	// styling
	prompt lipgloss.Style
	input  lipgloss.Style
	rowSel lipgloss.Style
	row    lipgloss.Style
	scope  lipgloss.Style
	footer lipgloss.Style
	final  lipgloss.Style
}

type match struct {
	idx       int
	indexes   []int // matched-rune positions in Name
}

func newModel(entries []Entry) *model {
	m := &model{all: entries, width: 80}
	m.refilter()
	m.prompt = lipgloss.NewStyle().Foreground(lipgloss.Color("12")).Bold(true)
	m.input = lipgloss.NewStyle()
	m.rowSel = lipgloss.NewStyle().Foreground(lipgloss.Color("0")).Background(lipgloss.Color("12"))
	m.row = lipgloss.NewStyle()
	m.scope = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	m.footer = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	m.final = lipgloss.NewStyle().Foreground(lipgloss.Color("10"))
	return m
}

func (m *model) Init() tea.Cmd { return nil }

func (m *model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if w, ok := msg.(tea.WindowSizeMsg); ok {
		m.width = w.Width
		if m.width < 30 {
			m.width = 30
		}
		return m, nil
	}
	k, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}
	switch k.Type {
	case tea.KeyCtrlC, tea.KeyEsc:
		m.cancelled = true
		return m, tea.Quit
	case tea.KeyEnter:
		if len(m.matches) > 0 {
			m.chosen = true
			return m, tea.Quit
		}
	case tea.KeyUp, tea.KeyCtrlP:
		if m.cursor > 0 {
			m.cursor--
		}
	case tea.KeyDown, tea.KeyCtrlN:
		if m.cursor < len(m.matches)-1 {
			m.cursor++
		}
	case tea.KeyBackspace:
		if len(m.query) > 0 {
			m.query = m.query[:len(m.query)-1]
			m.refilter()
		}
	case tea.KeyRunes:
		m.query += string(k.Runes)
		m.refilter()
	}
	return m, nil
}

func (m *model) refilter() {
	if m.query == "" {
		m.matches = make([]match, len(m.all))
		for i := range m.all {
			m.matches[i] = match{idx: i}
		}
		m.cursor = 0
		return
	}
	names := make([]string, len(m.all))
	for i, e := range m.all {
		names[i] = e.Name
	}
	res := fuzzy.Find(m.query, names)
	out := make([]match, 0, len(res))
	for _, r := range res {
		out = append(out, match{idx: r.Index, indexes: r.MatchedIndexes})
	}
	m.matches = out
	if m.cursor >= len(out) {
		m.cursor = 0
	}
}

func (m *model) View() string {
	if m.chosen {
		// Empty final frame: the caller prints whatever message fits the
		// command (`get` echos the value, `copy` echos "✓ copied").
		return ""
	}
	if m.cancelled {
		return "✗ cancelled\n"
	}
	w := m.width
	if w < 30 {
		w = 30
	}
	pad := func(s string) string {
		return lipgloss.NewStyle().Width(w).MaxWidth(w).Render(s)
	}
	padStyled := func(s string, st lipgloss.Style) string {
		return lipgloss.NewStyle().Width(w).MaxWidth(w).Inherit(st).Render(s)
	}
	var b strings.Builder
	queryLine := m.prompt.Render("? Search ") + m.input.Render(m.query+"_")
	b.WriteString(pad(queryLine))
	b.WriteByte('\n')
	const maxRows = 8
	n := len(m.matches)
	if n > maxRows {
		n = maxRows
	}
	// Layout: "▸ <name>  <scope>" — name takes ~60% of width, scope the rest.
	nameW := (w - 4) * 6 / 10
	if nameW < 12 {
		nameW = 12
	}
	scopeW := w - 4 - nameW - 2
	if scopeW < 6 {
		scopeW = 6
	}
	for i := 0; i < n; i++ {
		mm := m.matches[i]
		e := m.all[mm.idx]
		marker := "  "
		if i == m.cursor {
			marker = "> "
		}
		row := marker + truncPad(e.Name, nameW) + "  " + truncPad(scopeDisplay(e), scopeW)
		if i == m.cursor {
			b.WriteString(padStyled(row, m.rowSel))
		} else {
			b.WriteString(padStyled(row, m.row))
		}
		b.WriteByte('\n')
	}
	for i := n; i < maxRows; i++ {
		b.WriteString(pad(""))
		b.WriteByte('\n')
	}
	footer := fmt.Sprintf("%d/%d · ↑↓ · enter · esc", n, len(m.all))
	b.WriteString(padStyled(footer, m.footer))
	b.WriteByte('\n')
	return b.String()
}

// scopeDisplay returns the human-readable scope name. Falls back to a
// truncated scope_id when no label is set.
func scopeDisplay(e Entry) string {
	if e.ScopeLabel != "" {
		return e.ScopeLabel
	}
	return shortID(e.ScopeID)
}

// shortID renders "s_zpfh6…" from "s_zpfh64lov…".
func shortID(id string) string {
	if len(id) <= 9 {
		return id
	}
	return id[:8] + "…"
}

// truncPad clips s to width w (with a trailing "…" when clipped) and pads
// with spaces if shorter.
func truncPad(s string, w int) string {
	if w <= 0 {
		return ""
	}
	rs := []rune(s)
	if len(rs) > w {
		if w >= 2 {
			return string(rs[:w-1]) + "…"
		}
		return string(rs[:w])
	}
	if len(rs) < w {
		return s + strings.Repeat(" ", w-len(rs))
	}
	return s
}

func (m *model) selected() Entry {
	if len(m.matches) == 0 {
		return Entry{}
	}
	return m.all[m.matches[m.cursor].idx]
}

func (m *model) finalLine() string {
	e := m.selected()
	return m.final.Render("✓ " + e.Name)
}
