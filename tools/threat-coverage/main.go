// threat-coverage walks the fd0 codebase and verifies the
// bidirectional link between THREATS.md and source code.
//
// Two checks:
//
//  1. Every threat in the THREATS.md catalogue (T01-Tnn) whose
//     status is 🟢 / 🛡️ MUST have at least one `// THREAT: Tnn`
//     annotation in non-test source code. Statuses 🤝 (user
//     ceremony), 📋 (acknowledged limit), and ⛔ (out of scope)
//     are exempt because they have no specific code site to
//     annotate.
//
//  2. Every `// THREAT: Tnn` annotation in source code MUST
//     reference a threat that exists in the catalogue. Catches
//     typos (T7 vs T07), removed-but-not-cleaned-up references,
//     and threats renamed without updating annotations.
//
// Run: `go run ./tools/threat-coverage` from the repo root.
// Wired into `make lint` as the threat-coverage target.
package main

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// catalogueRow matches lines of the form "| T07 | 🛡️ | …" in
// the coverage matrix at §4 of THREATS.md. The status emoji is
// in the 2nd column.
var catalogueRowRE = regexp.MustCompile(`(?m)^\|\s*(T\d{2})\s*\|\s*([^|]+?)\s*\|`)

// threatHeaderRE matches the start of a THREAT annotation block:
// `// THREAT: ...` (any indentation). The body of the block may
// span multiple comment lines; `extractAnnotationsFromFile` walks
// the surrounding comment context and pulls every Tnn token
// from it.
var threatHeaderRE = regexp.MustCompile(`^\s*//\s*THREAT:\s*(.*)$`)

// commentLineRE matches any single-line `// ...` comment. Used to
// detect continuation lines in a multi-line THREAT block.
var commentLineRE = regexp.MustCompile(`^\s*//`)

// idTokenRE pulls every "T\d+" token from a string.
var idTokenRE = regexp.MustCompile(`T\d+`)

// requireAnnotation lists status emojis whose threats MUST have
// at least one inline annotation. The check uses
// `requiresAnnotation(status)` for the heuristic so this map is
// just a fast-path; the heuristic catches multi-emoji statuses.
var requireAnnotation = map[string]bool{
	"🟢":  true,
	"🛡️":  true,
}

// loadCatalogue reads THREATS.md and returns all (id, status)
// pairs from the §4 coverage matrix.
func loadCatalogue(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	matches := catalogueRowRE.FindAllStringSubmatch(string(data), -1)
	out := map[string]string{}
	for _, m := range matches {
		id := m[1]
		status := strings.TrimSpace(m[2])
		// Skip the header row "T01 | Status | …" if it ever
		// happens to match (the regex shouldn't but be safe).
		if id == "" || strings.Contains(status, "Status") {
			continue
		}
		out[id] = status
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no threat rows found in %s — catalogue regex broken?", path)
	}
	return out, nil
}

// extractAnnotationsFromFile parses Go source and returns every
// Tnn token referenced by a `// THREAT: ...` annotation block.
// Multi-line blocks (continuation comment lines starting with
// `//` but not with `// THREAT:`) are folded into the active
// block, so:
//
//	// THREAT: T09 (panics),
//	//         T11 (mismatched halves).
//	func ParseEd25519Priv(...) { ... }
//
// yields {T09, T11}. Returns the IDs in source order, possibly
// with duplicates (the caller dedups per file by appending to a
// slice and using a set later if needed).
func extractAnnotationsFromFile(content string) []string {
	lines := strings.Split(content, "\n")
	var ids []string
	inBlock := false
	for _, line := range lines {
		if m := threatHeaderRE.FindStringSubmatch(line); m != nil {
			// Start of a new annotation block. Pull IDs from
			// this line's body.
			ids = append(ids, idTokenRE.FindAllString(m[1], -1)...)
			inBlock = true
			continue
		}
		if inBlock {
			// Continuation line iff it's still a `//` comment
			// (otherwise the block ended at the previous line,
			// possibly directly above a function declaration).
			if commentLineRE.MatchString(line) {
				ids = append(ids, idTokenRE.FindAllString(line, -1)...)
				continue
			}
			inBlock = false
		}
	}
	return ids
}

// scanAnnotations walks the repo and returns a map id →
// list-of-files for every // THREAT: Tnn annotation in
// non-test Go files.
func scanAnnotations(root string) (map[string][]string, []string, error) {
	idToFiles := map[string][]string{}
	var unknownIDs []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// Don't skip the walk root itself — its name might be
			// "." or any path with a leading dot. The hidden-dir
			// guard applies only to descendants.
			if p == root {
				return nil
			}
			name := d.Name()
			if name == "vendor" || strings.HasPrefix(name, ".") || name == "node_modules" {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") {
			return nil
		}
		if strings.HasSuffix(p, "_test.go") {
			return nil // tests don't carry the canonical annotation
		}
		// gosec G122 false-positive — this is a doc-ish tool
		// running over the repo it lives in. Root is a fixed
		// working directory; no untrusted symlink traversal.
		body, rerr := os.ReadFile(p) // #nosec G304 -- repo-local doc tool, not a server endpoint
		if rerr != nil {
			return rerr
		}
		for _, id := range extractAnnotationsFromFile(string(body)) {
			idToFiles[id] = append(idToFiles[id], p)
		}
		return nil
	})
	return idToFiles, unknownIDs, err
}

// requiresAnnotation returns true if the status mandates at least
// one inline `// THREAT: Tnn` annotation in non-test code.
//
// Codex review note: emoji status cells can be entered with or
// without the U+FE0F variation selector that disambiguates
// "🛡️" (presentation: emoji) from "🛡" (presentation: text). They
// look identical in most editors but compare as different byte
// sequences (`f09f9ba1efb88f` vs `f09f9ba1`). To keep the CI
// guarantee robust, we check for the BASE rune of each
// structural emoji — that catches both variants.
func requiresAnnotation(status string) bool {
	if requireAnnotation[status] {
		return true
	}
	// Use base runes (without the optional VS-16 selector) so a
	// human accidentally typing the bare-presentation form
	// doesn't silently exempt a structural threat from
	// annotation coverage.
	for _, baseRune := range []string{"🟢", "🛡"} {
		if strings.Contains(status, baseRune) {
			return true
		}
	}
	return false
}

func main() {
	root := "."
	if len(os.Args) > 1 {
		root = os.Args[1]
	}
	threatsPath := filepath.Join(root, "THREATS.md")

	catalogue, err := loadCatalogue(threatsPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "threat-coverage:", err)
		os.Exit(2)
	}
	annotations, _, err := scanAnnotations(root)
	if err != nil {
		fmt.Fprintln(os.Stderr, "threat-coverage: scan:", err)
		os.Exit(2)
	}

	// Check 1: every threat that requires a code annotation has one.
	var missing []string
	for id, status := range catalogue {
		if !requiresAnnotation(status) {
			continue
		}
		if len(annotations[id]) == 0 {
			missing = append(missing, fmt.Sprintf("%s [%s]", id, status))
		}
	}

	// Check 2: every annotation references a known threat.
	var unknown []string
	for id, files := range annotations {
		if _, ok := catalogue[id]; !ok {
			// Sort + dedup file list for stable output.
			sort.Strings(files)
			seen := map[string]bool{}
			var dedup []string
			for _, f := range files {
				if !seen[f] {
					seen[f] = true
					dedup = append(dedup, f)
				}
			}
			unknown = append(unknown, fmt.Sprintf("%s in %s", id, strings.Join(dedup, ", ")))
		}
	}

	sort.Strings(missing)
	sort.Strings(unknown)

	fail := false
	if len(missing) > 0 {
		fmt.Fprintln(os.Stderr, "threat-coverage: catalogued threats missing inline annotation:")
		for _, m := range missing {
			fmt.Fprintln(os.Stderr, "  -", m)
		}
		fail = true
	}
	if len(unknown) > 0 {
		fmt.Fprintln(os.Stderr, "threat-coverage: annotations reference unknown threat IDs:")
		for _, u := range unknown {
			fmt.Fprintln(os.Stderr, "  -", u)
		}
		fail = true
	}
	if fail {
		fmt.Fprintf(os.Stderr, "\nthreat-coverage: %d catalogue, %d annotated\n",
			len(catalogue), len(annotations))
		os.Exit(1)
	}
	fmt.Printf("threat-coverage: ok — %d catalogue rows, %d annotation IDs\n",
		len(catalogue), len(annotations))
}
