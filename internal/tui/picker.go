package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// PickerItem is one row in a single-select picker.
type PickerItem struct {
	ID    string // returned to caller on selection
	Label string // primary line shown to user
	Hint  string // optional secondary text (greyed out)
}

// PickerResult is what RunPicker returns. ID is empty when the user cancels.
type PickerResult struct {
	ID    string
	Label string
}

// RunPicker shows a single-select inline list. Up/Down moves the cursor,
// Enter selects, Esc/Ctrl-C cancels. Same inline rendering policy as Run.
func RunPicker(prompt string, items []PickerItem) (PickerResult, error) {
	if len(items) == 0 {
		return PickerResult{}, fmt.Errorf("picker: empty items")
	}
	m := &pickerModel{items: items, prompt: prompt, width: 80}
	p := tea.NewProgram(m, tea.WithOutput(stderr{}))
	final, err := p.Run()
	if err != nil {
		return PickerResult{}, err
	}
	mm := final.(*pickerModel)
	if mm.cancelled {
		return PickerResult{}, nil
	}
	it := mm.items[mm.cursor]
	return PickerResult{ID: it.ID, Label: it.Label}, nil
}

type pickerModel struct {
	items     []PickerItem
	cursor    int
	chosen    bool
	cancelled bool
	prompt    string
	width     int
}

func (m *pickerModel) Init() tea.Cmd { return nil }

func (m *pickerModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
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
		m.chosen = true
		return m, tea.Quit
	case tea.KeyUp, tea.KeyCtrlP:
		if m.cursor > 0 {
			m.cursor--
		}
	case tea.KeyDown, tea.KeyCtrlN:
		if m.cursor < len(m.items)-1 {
			m.cursor++
		}
	}
	return m, nil
}

func (m *pickerModel) View() string {
	if m.chosen || m.cancelled {
		return ""
	}
	w := m.width
	if w < 30 {
		w = 30
	}
	pad := func(s string) string {
		return lipgloss.NewStyle().Width(w).MaxWidth(w).Render(s)
	}
	sel := lipgloss.NewStyle().Foreground(lipgloss.Color("0")).Background(lipgloss.Color("12"))
	hintStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("8"))

	var b strings.Builder
	promptStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("12")).Bold(true)
	b.WriteString(pad(promptStyle.Render("? " + m.prompt)))
	b.WriteByte('\n')

	labelW := (w - 4) * 5 / 10
	if labelW < 8 {
		labelW = 8
	}
	hintW := w - 4 - labelW - 2
	if hintW < 0 {
		hintW = 0
	}
	for i, it := range m.items {
		marker := "  "
		if i == m.cursor {
			marker = "> "
		}
		hint := truncPad(it.Hint, hintW)
		row := marker + truncPad(it.Label, labelW) + "  " + hintStyle.Render(hint)
		if i == m.cursor {
			b.WriteString(lipgloss.NewStyle().Width(w).MaxWidth(w).Inherit(sel).Render(row))
		} else {
			b.WriteString(pad(row))
		}
		b.WriteByte('\n')
	}
	footer := lipgloss.NewStyle().Foreground(lipgloss.Color("8")).Render("↑↓ select · enter · esc")
	b.WriteString(pad(footer))
	b.WriteByte('\n')
	return b.String()
}
