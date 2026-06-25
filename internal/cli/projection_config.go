package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/valentinkolb/fd0.sh/internal/fdhome"
)

func setProjectionConfig(section string, enabled, autoMerge bool) error {
	paths, err := fdhome.Resolve()
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(paths.Config)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	doc := string(raw)
	doc = upsertTOMLBool(doc, section, "enabled", enabled)
	doc = upsertTOMLBool(doc, section, "auto_merge", autoMerge)
	if err := os.MkdirAll(parentDir(paths.Config), 0o700); err != nil {
		return err
	}
	return writeFileAtomic(paths.Config, []byte(doc), 0o600)
}

func upsertTOMLBool(doc, section, key string, value bool) string {
	line := fmt.Sprintf("%s = %t", key, value)
	lines := splitTOMLLines(doc)
	header := "[" + section + "]"

	sectionStart := -1
	sectionEnd := len(lines)
	for i, l := range lines {
		trim := strings.TrimSpace(l)
		if !strings.HasPrefix(trim, "[") || !strings.HasSuffix(trim, "]") {
			continue
		}
		if sectionStart >= 0 {
			sectionEnd = i
			break
		}
		if trim == header {
			sectionStart = i
		}
	}

	if sectionStart < 0 {
		if len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) != "" {
			lines = append(lines, "")
		}
		lines = append(lines, header, line)
		return strings.Join(lines, "\n") + "\n"
	}

	for i := sectionStart + 1; i < sectionEnd; i++ {
		name, ok := tomlKeyName(lines[i])
		if ok && name == key {
			lines[i] = line
			return strings.Join(lines, "\n") + "\n"
		}
	}

	lines = append(lines[:sectionEnd], append([]string{line}, lines[sectionEnd:]...)...)
	return strings.Join(lines, "\n") + "\n"
}

func splitTOMLLines(doc string) []string {
	if doc == "" {
		return nil
	}
	lines := strings.Split(doc, "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

func tomlKeyName(line string) (string, bool) {
	trim := strings.TrimSpace(line)
	if trim == "" || strings.HasPrefix(trim, "#") {
		return "", false
	}
	k, _, ok := strings.Cut(trim, "=")
	if !ok {
		return "", false
	}
	return strings.TrimSpace(k), true
}
