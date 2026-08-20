package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"unicode"

	"golang.org/x/term"
)

// IsTTY returns true iff fd is an interactive terminal.
func IsTTY(f *os.File) bool { return term.IsTerminal(int(f.Fd())) }

// terminalSafe neutralizes control characters in untrusted display text while
// preserving ordinary Unicode. Scope labels can be authored by another member
// and must never become terminal instructions when rendered locally.
func terminalSafe(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return '?'
		}
		return r
	}, s)
}

var (
	stdinOnce   sync.Once
	stdinReader *bufio.Reader

	hiddenTTYState struct {
		sync.Mutex
		fd    int
		state *term.State
	}
)

func sharedStdin() *bufio.Reader {
	stdinOnce.Do(func() { stdinReader = bufio.NewReader(os.Stdin) })
	return stdinReader
}

// readHiddenTTY reads one line without echo while keeping enough state for the
// process-wide interrupt handler to repair the terminal before it exits. The
// x/term helper restores the state when it returns normally; the explicit
// snapshot covers SIGINT, where memguard exits the process from another
// goroutine before ReadPassword's deferred restore can run.
func readHiddenTTY(stdin, stderr *os.File, prompt string) ([]byte, error) {
	fd := int(stdin.Fd())
	state, err := term.GetState(fd)
	if err != nil {
		return nil, err
	}
	hiddenTTYState.Lock()
	hiddenTTYState.fd = fd
	hiddenTTYState.state = state
	hiddenTTYState.Unlock()
	defer RestoreTerminal()

	fmt.Fprint(stderr, prompt)
	b, err := term.ReadPassword(fd)
	fmt.Fprintln(stderr)
	return b, err
}

// RestoreTerminal repairs an active hidden-input terminal and reports whether
// there was one to restore. It is safe to call from the process-wide interrupt
// handler and is otherwise a no-op.
func RestoreTerminal() bool {
	hiddenTTYState.Lock()
	defer hiddenTTYState.Unlock()
	if hiddenTTYState.state == nil {
		return false
	}
	err := term.Restore(hiddenTTYState.fd, hiddenTTYState.state)
	hiddenTTYState.fd = 0
	hiddenTTYState.state = nil
	return err == nil
}

// ReadPassphrase prompts on stderr and reads a passphrase from stdin without
// echo when stdin is a TTY. On a non-TTY (pipes, CI) it reads a single line
// from a process-shared bufio reader.
func ReadPassphrase(prompt string) ([]byte, error) {
	if IsTTY(os.Stdin) {
		b, err := readHiddenTTY(os.Stdin, os.Stderr, prompt)
		if err != nil {
			return nil, err
		}
		if len(b) == 0 {
			return nil, errors.New("passphrase cannot be empty")
		}
		return b, nil
	}
	r := sharedStdin()
	line, err := r.ReadString('\n')
	if err != nil && err != io.EOF {
		return nil, err
	}
	for len(line) > 0 && (line[len(line)-1] == '\n' || line[len(line)-1] == '\r') {
		line = line[:len(line)-1]
	}
	if line == "" {
		return nil, errors.New("passphrase cannot be empty")
	}
	return []byte(line), nil
}

// ReadOptionalPIN prompts on stderr and reads a (possibly-empty) PIN
// from stdin. Mirrors ReadPassphrase's TTY/non-TTY split; the only
// difference is that an empty input is a valid response (signalling
// "touch-only YubiKey, no PIN policy"). Returns a nil byte slice for
// empty input so the caller can dispatch on len(pin) == 0.
func ReadOptionalPIN(prompt string) ([]byte, error) {
	if IsTTY(os.Stdin) {
		b, err := readHiddenTTY(os.Stdin, os.Stderr, prompt)
		if err != nil {
			return nil, err
		}
		if len(b) == 0 {
			return nil, nil
		}
		return b, nil
	}
	r := sharedStdin()
	line, err := r.ReadString('\n')
	if err != nil && err != io.EOF {
		return nil, err
	}
	for len(line) > 0 && (line[len(line)-1] == '\n' || line[len(line)-1] == '\r') {
		line = line[:len(line)-1]
	}
	if line == "" {
		return nil, nil
	}
	return []byte(line), nil
}

// ReadPassphraseConfirm prompts twice and rejects if the two reads differ.
func ReadPassphraseConfirm(prompt1, prompt2 string) ([]byte, error) {
	a, err := ReadPassphrase(prompt1)
	if err != nil {
		return nil, err
	}
	b, err := ReadPassphrase(prompt2)
	if err != nil {
		return nil, err
	}
	if string(a) != string(b) {
		return nil, errors.New("passphrases differ")
	}
	return a, nil
}
