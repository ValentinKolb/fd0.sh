//go:build yubikey

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/valentinkolb/fd0.sh/internal/crypto/yubikey"
)

func run() error {
	var (
		count    = flag.Int("count", 5, "number of vectors to record")
		pin      = flag.String("pin", os.Getenv("YUBIKEY_PIN"), "PIN; default $YUBIKEY_PIN")
		firmware = flag.String("firmware", "", "firmware string written into the fixture (REQUIRED on hardware day)")
		output   = flag.String("output", "-", "output path; - = stdout")
	)
	flag.Parse()

	if *firmware == "" {
		return fmt.Errorf("--firmware is required (run `ykman info` to read it from the card; the recorder does not auto-detect in this build)")
	}

	card, err := yubikey.Open(yubikey.OpenOptions{
		// v1 only supports SlotKeyManagement; the fixture's textual
		// slot field is hard-coded in Record() to match.
		Slot: yubikey.SlotKeyManagement,
		PIN:  *pin,
	})
	if err != nil {
		return fmt.Errorf("open YubiKey: %w", err)
	}
	defer card.Close()

	fixture, err := Record(card, recordOptions{
		Count:    *count,
		Firmware: *firmware,
	})
	if err != nil {
		return err
	}

	body, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal fixture: %w", err)
	}
	body = append(body, '\n')

	if *output == "-" {
		_, err := os.Stdout.Write(body)
		return err
	}
	return atomicWriteFile(*output, body, 0o600)
}

// atomicWriteFile writes data to path via .tmp + rename. If Record
// fails the target file is never opened, so the user's existing
// fixture (if any) is preserved. The conventional `> v1.json` shell
// redirect can't offer this guarantee — it truncates the target
// before the program starts.
func atomicWriteFile(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return fmt.Errorf("write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename %s -> %s: %w", tmp, path, err)
	}
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "fd0-yubikey-record:", err)
		os.Exit(1)
	}
}
