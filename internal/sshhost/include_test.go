package sshhost

import (
	"os"
	"path/filepath"
	"testing"
)

func TestHasInclude(t *testing.T) {
	tmp := t.TempDir()
	fd0Conf := filepath.Join(tmp, "fd0.conf")
	if err := os.WriteFile(fd0Conf, []byte("# fd0\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name      string
		body      string
		wantTrue  bool
	}{
		{"present plain", "Include " + fd0Conf + "\n", true},
		{"present indented", "    Include " + fd0Conf + "\n", true},
		{"present lower-case", "include " + fd0Conf + "\n", true},
		{"present with quotes", "Include \"" + fd0Conf + "\"\n", true},
		{"present amongst other lines", "# comment\n\nHost foo\n  HostName x\n\nInclude " + fd0Conf + "\nHost bar\n  HostName y\n", true},
		{"only commented", "# Include " + fd0Conf + "\n", false},
		{"different path", "Include /etc/ssh/other.conf\n", false},
		{"empty file", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := filepath.Join(tmp, "config-"+c.name)
			if err := os.WriteFile(cfg, []byte(c.body), 0o644); err != nil {
				t.Fatal(err)
			}
			got, err := HasInclude(cfg, fd0Conf)
			if err != nil {
				t.Fatal(err)
			}
			if got != c.wantTrue {
				t.Errorf("got=%v want=%v", got, c.wantTrue)
			}
		})
	}
}

func TestHasIncludeMissingFile(t *testing.T) {
	// Non-existent ssh_config is not an error — caller treats as
	// "no include yet".
	got, err := HasInclude("/no/such/file", "/no/such/include")
	if err != nil {
		t.Fatalf("expected nil err on missing file, got %v", err)
	}
	if got {
		t.Error("expected false on missing file")
	}
}

func TestHasIncludeMultiplePathsPerDirective(t *testing.T) {
	tmp := t.TempDir()
	fd0Conf := filepath.Join(tmp, "fd0.conf")
	otherConf := filepath.Join(tmp, "other.conf")
	_ = os.WriteFile(fd0Conf, []byte("# fd0\n"), 0o644)
	_ = os.WriteFile(otherConf, []byte("# other\n"), 0o644)
	cfg := filepath.Join(tmp, "config")
	body := "Include " + otherConf + " " + fd0Conf + "\n"
	_ = os.WriteFile(cfg, []byte(body), 0o644)
	got, err := HasInclude(cfg, fd0Conf)
	if err != nil {
		t.Fatal(err)
	}
	if !got {
		t.Error("expected Include with multiple paths to match the target")
	}
}
