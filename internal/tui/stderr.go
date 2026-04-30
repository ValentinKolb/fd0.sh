package tui

import "os"

func _stderrWrite(p []byte) (int, error) { return os.Stderr.Write(p) }
