package cli

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/valentinkolb/fd0.sh/internal/tui"
)

// RunGet implements `fd0 get [NAME]`.
//
//	NAME present       → print value to stdout (newline by default; --raw to omit)
//	NAME absent + TTY  → interactive searcher; selection prints value to stdout
//	NAME absent + non-TTY → error
//
// `fd0 get` never touches the clipboard. Use `fd0 copy` for that.
func RunGet(ctx context.Context, scopeID, name string, raw bool) error {
	if name != "" {
		val, err := RunSecretGet(ctx, scopeID, name)
		if err != nil {
			return err
		}
		if raw {
			fmt.Print(val)
		} else {
			fmt.Println(val)
		}
		return nil
	}
	if !IsTTY(os.Stdin) || !IsTTY(os.Stderr) {
		return errors.New("interactive get requires a TTY (or pass NAME explicitly)")
	}
	entries, s, err := CollectAllSecrets(ctx)
	if err != nil {
		return err
	}
	defer s.Close()
	if len(entries) == 0 {
		fmt.Fprintln(os.Stderr, "(no secrets)")
		return nil
	}
	tuiEntries := make([]tui.Entry, len(entries))
	for i, e := range entries {
		tuiEntries[i] = tui.Entry{ScopeID: e.ScopeID, ScopeLabel: e.ScopeLabel, ID: e.ID, Name: e.Name, Type: e.Type}
	}
	sel, err := tui.Run(tuiEntries)
	if err != nil {
		return err
	}
	if sel.Entry.Name == "" {
		return nil
	}
	val, err := s.GetSecretByName(sel.Entry.ScopeID, sel.Entry.Name)
	if err != nil {
		return err
	}
	if raw {
		fmt.Print(val)
	} else {
		fmt.Println(val)
	}
	return nil
}
