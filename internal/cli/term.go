package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	"golang.org/x/term"
)

// IsTTY returns true iff fd is an interactive terminal.
func IsTTY(f *os.File) bool { return term.IsTerminal(int(f.Fd())) }

var (
	stdinOnce   sync.Once
	stdinReader *bufio.Reader
)

func sharedStdin() *bufio.Reader {
	stdinOnce.Do(func() { stdinReader = bufio.NewReader(os.Stdin) })
	return stdinReader
}

// ReadPassphrase prompts on stderr and reads a passphrase from stdin without
// echo when stdin is a TTY. On a non-TTY (pipes, CI) it reads a single line
// from a process-shared bufio reader.
func ReadPassphrase(prompt string) ([]byte, error) {
	if IsTTY(os.Stdin) {
		fmt.Fprint(os.Stderr, prompt)
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
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
