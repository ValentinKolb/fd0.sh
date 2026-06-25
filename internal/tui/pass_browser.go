package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/sahilm/fuzzy"
)

const (
	PassActionCopyPassword = "copy-password"
	PassActionCopyUsername = "copy-username"
	PassActionCopyTOTP     = "copy-totp"
)

type PassBrowserItem struct {
	ID     string
	Title  string
	Scope  string
	URL    string
	Search string
	Fields []PassBrowserField
}

type PassBrowserField struct {
	Path     string
	Type     string
	Masked   string
	Revealed string
}

type PassBrowserResult struct {
	ItemID string
	Action string
}

func RunPassBrowser(items []PassBrowserItem, initialQuery string) (PassBrowserResult, error) {
	if len(items) == 0 {
		return PassBrowserResult{}, fmt.Errorf("pass browser: empty items")
	}
	m := newPassBrowserModel(items, initialQuery)
	p := tea.NewProgram(m, tea.WithOutput(stderr{}))
	final, err := p.Run()
	if err != nil {
		return PassBrowserResult{}, err
	}
	mm := final.(*passBrowserModel)
	if mm.cancelled || mm.action == "" {
		return PassBrowserResult{}, nil
	}
	return PassBrowserResult{ItemID: mm.selected().ID, Action: mm.action}, nil
}

type passBrowserMode int

const (
	passBrowserList passBrowserMode = iota
	passBrowserDetail
)

type passBrowserModel struct {
	all       []PassBrowserItem
	matches   []passBrowserMatch
	query     string
	cursor    int
	mode      passBrowserMode
	reveal    bool
	action    string
	cancelled bool
	width     int

	prompt lipgloss.Style
	sel    lipgloss.Style
	dim    lipgloss.Style
}

type passBrowserMatch struct {
	idx int
}

func newPassBrowserModel(items []PassBrowserItem, initialQuery string) *passBrowserModel {
	m := &passBrowserModel{
		all:    items,
		query:  strings.TrimSpace(initialQuery),
		width:  80,
		prompt: lipgloss.NewStyle().Foreground(lipgloss.Color("12")).Bold(true),
		sel:    lipgloss.NewStyle().Foreground(lipgloss.Color("0")).Background(lipgloss.Color("12")),
		dim:    lipgloss.NewStyle().Foreground(lipgloss.Color("8")),
	}
	m.refilter()
	return m
}

func (m *passBrowserModel) Init() tea.Cmd { return nil }

func (m *passBrowserModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if w, ok := msg.(tea.WindowSizeMsg); ok {
		m.width = w.Width
		if m.width < 40 {
			m.width = 40
		}
		return m, nil
	}
	k, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}
	if m.mode == passBrowserDetail {
		return m.updateDetail(k)
	}
	return m.updateList(k)
}

func (m *passBrowserModel) updateList(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch k.Type {
	case tea.KeyCtrlC, tea.KeyEsc:
		m.cancelled = true
		return m, tea.Quit
	case tea.KeyEnter:
		if len(m.matches) > 0 {
			m.mode = passBrowserDetail
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
		if strings.ToLower(string(k.Runes)) == "q" && m.query == "" {
			m.cancelled = true
			return m, tea.Quit
		}
		m.query += string(k.Runes)
		m.refilter()
	}
	return m, nil
}

func (m *passBrowserModel) updateDetail(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch k.Type {
	case tea.KeyCtrlC:
		m.cancelled = true
		return m, tea.Quit
	case tea.KeyEsc:
		m.mode = passBrowserList
	case tea.KeyRunes:
		switch strings.ToLower(string(k.Runes)) {
		case "q":
			m.cancelled = true
			return m, tea.Quit
		case "p":
			m.action = PassActionCopyPassword
			return m, tea.Quit
		case "u":
			m.action = PassActionCopyUsername
			return m, tea.Quit
		case "t":
			m.action = PassActionCopyTOTP
			return m, tea.Quit
		case "r":
			m.reveal = !m.reveal
		}
	}
	return m, nil
}

func (m *passBrowserModel) refilter() {
	if m.query == "" {
		m.matches = make([]passBrowserMatch, len(m.all))
		for i := range m.all {
			m.matches[i] = passBrowserMatch{idx: i}
		}
		m.cursor = 0
		return
	}
	haystack := make([]string, len(m.all))
	for i, it := range m.all {
		haystack[i] = it.Search
	}
	res := fuzzy.Find(m.query, haystack)
	out := make([]passBrowserMatch, 0, len(res))
	for _, r := range res {
		out = append(out, passBrowserMatch{idx: r.Index})
	}
	m.matches = out
	if m.cursor >= len(out) {
		m.cursor = 0
	}
}

func (m *passBrowserModel) View() string {
	if m.action != "" {
		return ""
	}
	if m.cancelled {
		return "cancelled\n"
	}
	if m.mode == passBrowserDetail {
		return m.detailView()
	}
	return m.listView()
}

func (m *passBrowserModel) listView() string {
	w := m.safeWidth()
	var b strings.Builder
	b.WriteString(m.pad(m.prompt.Render("? Pass ") + m.query + "_"))
	b.WriteByte('\n')
	const maxRows = 8
	n := len(m.matches)
	if n > maxRows {
		n = maxRows
	}
	titleW := (w - 4) * 45 / 100
	scopeW := (w - 4) * 20 / 100
	urlW := w - 4 - titleW - scopeW - 4
	if urlW < 8 {
		urlW = 8
	}
	for i := 0; i < n; i++ {
		it := m.all[m.matches[i].idx]
		marker := "  "
		if i == m.cursor {
			marker = "> "
		}
		row := marker + truncPad(it.Title, titleW) + "  " + truncPad(it.Scope, scopeW) + "  " + m.dim.Render(truncPad(it.URL, urlW))
		if i == m.cursor {
			b.WriteString(m.padStyled(row, m.sel))
		} else {
			b.WriteString(m.pad(row))
		}
		b.WriteByte('\n')
	}
	for i := n; i < maxRows; i++ {
		b.WriteString(m.pad(""))
		b.WriteByte('\n')
	}
	b.WriteString(m.padStyled(fmt.Sprintf("%d/%d · type search · up/down · enter details · esc/q", len(m.matches), len(m.all)), m.dim))
	b.WriteByte('\n')
	return b.String()
}

func (m *passBrowserModel) detailView() string {
	w := m.safeWidth()
	it := m.selected()
	var b strings.Builder
	b.WriteString(m.pad(m.prompt.Render(it.Title) + "  " + m.dim.Render(it.Scope)))
	b.WriteByte('\n')
	if it.URL != "" {
		b.WriteString(m.pad(m.dim.Render(it.URL)))
		b.WriteByte('\n')
	}
	b.WriteByte('\n')
	const maxFields = 12
	pathW := (w - 4) * 45 / 100
	typeW := 8
	valueW := w - 4 - pathW - typeW - 4
	if valueW < 8 {
		valueW = 8
	}
	n := len(it.Fields)
	if n > maxFields {
		n = maxFields
	}
	for i := 0; i < n; i++ {
		f := it.Fields[i]
		value := f.Masked
		if m.reveal {
			value = f.Revealed
		}
		row := "  " + truncPad(f.Path, pathW) + "  " + truncPad(f.Type, typeW) + "  " + truncPad(value, valueW)
		b.WriteString(m.pad(row))
		b.WriteByte('\n')
	}
	if len(it.Fields) > maxFields {
		b.WriteString(m.pad(m.dim.Render(fmt.Sprintf("  ... %d more fields", len(it.Fields)-maxFields))))
		b.WriteByte('\n')
	}
	b.WriteString(m.padStyled("p copy password · u copy username · t copy totp · r reveal · esc back · q quit", m.dim))
	b.WriteByte('\n')
	return b.String()
}

func (m *passBrowserModel) selected() PassBrowserItem {
	if len(m.matches) == 0 {
		return PassBrowserItem{}
	}
	return m.all[m.matches[m.cursor].idx]
}

func (m *passBrowserModel) safeWidth() int {
	if m.width < 40 {
		return 40
	}
	return m.width
}

func (m *passBrowserModel) pad(s string) string {
	return lipgloss.NewStyle().Width(m.safeWidth()).MaxWidth(m.safeWidth()).Render(s)
}

func (m *passBrowserModel) padStyled(s string, st lipgloss.Style) string {
	return lipgloss.NewStyle().Width(m.safeWidth()).MaxWidth(m.safeWidth()).Inherit(st).Render(s)
}
