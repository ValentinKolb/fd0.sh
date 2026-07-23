package cli

import "testing"

func TestTerminalSafeNeutralizesControlCharacters(t *testing.T) {
	input := "work\x1b]52;c;stolen\a\n\t\u0085safe"
	got := terminalSafe(input)
	want := "work?]52;c;stolen????safe"
	if got != want {
		t.Fatalf("terminalSafe(%q) = %q, want %q", input, got, want)
	}
}

func TestTerminalSafePreservesOrdinaryUnicode(t *testing.T) {
	const input = "Kolb Antik - Schlüssel"
	if got := terminalSafe(input); got != input {
		t.Fatalf("terminalSafe(%q) = %q", input, got)
	}
}
