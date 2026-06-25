package cli

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func confirmDanger(yes bool, prompt string) error {
	if yes || !IsTTY(os.Stdin) || !IsTTY(os.Stderr) {
		return nil
	}
	fmt.Fprintf(os.Stderr, "%s [y/N] ", prompt)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return err
	}
	line = strings.TrimSpace(strings.ToLower(line))
	if line != "y" && line != "yes" {
		return fmt.Errorf("aborted")
	}
	return nil
}

func hintSync() {
	stderrln("  run `fd0 sync` to publish this change")
}

func hintSyncForPeers() {
	stderrln("  run `fd0 sync` so other devices and members see this change")
}
