// Package witnesses_test validates all witness config files in the witnesses/
// directory against the tlog-policy witness file format:
//
//	# Comments start with '#'; blank lines are ignored.
//	witness <name> <vkey> [<url>]
//	group <name> <threshold|any|all> <member>...
//
// "log" and "quorum" lines are not permitted.
// Each file must define at least one witness.
// Names (witness and group) must be unique within a file.
// Group members must reference names defined earlier in the same file.
// The vkey field of a witness line must follow the <name>+<keyid>+<key> format.
// The URL field of a witness line is required.
package witnesses_test

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/google-tlog-witness/internal/vkey"
)

// validateWitnessFile checks the structure and correctness of a single witness
// config file, returning a list of human-readable error strings (one per
// violation).
func validateWitnessFile(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return []string{fmt.Sprintf("cannot open file: %v", err)}
	}
	defer f.Close()

	var errs []string
	definedNames := make(map[string]bool) // names defined so far (witness + group)
	witnessCount := 0
	lineNum := 0

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lineNum++
		raw := scanner.Text()
		trimmed := strings.TrimSpace(raw)

		// Blank lines and comments are allowed.
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		fields := strings.Fields(trimmed)
		keyword := fields[0]

		switch keyword {
		case "witness":
			// witness <name> <vkey> <url>
			// Required: keyword + name + vkey + url = exactly 4 fields.
			if len(fields) != 4 {
				errs = append(errs, fmt.Sprintf("line %d: witness line must have exactly 4 fields (keyword name vkey url), got %d: %q", lineNum, len(fields), trimmed))
				// Still extract what we can for further validation.
				if len(fields) < 2 {
					continue
				}
			}
			name := fields[1]
			var vkeyStr, rawURL string
			if len(fields) >= 3 {
				vkeyStr = fields[2]
			}
			if len(fields) >= 4 {
				rawURL = fields[3]
			}

			// Validate name uniqueness.
			if definedNames[name] {
				errs = append(errs, fmt.Sprintf("line %d: duplicate name %q", lineNum, name))
			} else {
				definedNames[name] = true
			}

			// Validate vkey format: <origin>+<keyid>+<base64key>.
			if vkeyStr != "" {
				if vkeyErrs, _ := vkey.Validate(vkeyStr, lineNum); len(vkeyErrs) > 0 {
					errs = append(errs, vkeyErrs...)
				}
			}

			// Validate required URL field.
			if rawURL != "" {
				if u, err := url.Parse(rawURL); err != nil || u.Scheme == "" || u.Host == "" {
					errs = append(errs, fmt.Sprintf("line %d: invalid URL %q: %v", lineNum, rawURL, err))
				}
			}

			witnessCount++

		case "group":
			// group <name> <threshold|any|all> <member>...
			// Minimum: keyword + name + threshold + one member = 4 fields.
			if len(fields) < 4 {
				errs = append(errs, fmt.Sprintf("line %d: group line must have at least 4 fields (keyword name threshold member...), got %d: %q", lineNum, len(fields), trimmed))
				continue
			}
			name := fields[1]
			threshold := fields[2]
			members := fields[3:]

			// Validate name uniqueness.
			if definedNames[name] {
				errs = append(errs, fmt.Sprintf("line %d: duplicate name %q", lineNum, name))
			} else {
				definedNames[name] = true
			}

			// Validate threshold.
			if threshold != "any" && threshold != "all" {
				// Must be a positive integer.
				n := 0
				if _, err := fmt.Sscanf(threshold, "%d", &n); err != nil || n <= 0 {
					errs = append(errs, fmt.Sprintf("line %d: group threshold must be \"any\", \"all\", or a positive integer, got %q", lineNum, threshold))
				}
			}

			// Validate that all members reference previously-defined names.
			for _, member := range members {
				if !definedNames[member] {
					errs = append(errs, fmt.Sprintf("line %d: group %q references undefined name %q", lineNum, name, member))
				}
			}

		case "log", "quorum":
			errs = append(errs, fmt.Sprintf("line %d: %q lines are not permitted in witness files", lineNum, keyword))

		default:
			errs = append(errs, fmt.Sprintf("line %d: unrecognised keyword %q", lineNum, keyword))
		}
	}

	if err := scanner.Err(); err != nil {
		errs = append(errs, fmt.Sprintf("scanner error: %v", err))
	}

	if witnessCount == 0 {
		errs = append(errs, "file defines no witness lines")
	}

	return errs
}



// TestWitnessFiles validates every .txt file in the witnesses/ directory.
func TestWitnessFiles(t *testing.T) {
	// The test binary runs with the package source directory as the working
	// directory under Bazel (via runfiles), so "." is witnesses/.
	// When run with "go test ./witnesses/", the cwd is the package dir.
	matches, err := filepath.Glob("*.txt")
	if err != nil {
		t.Fatalf("globbing for *.txt: %v", err)
	}
	if len(matches) == 0 {
		t.Fatal("no .txt files found in witnesses/ — check the test working directory")
	}

	for _, path := range matches {
		t.Run(strings.TrimSuffix(path, ".txt"), func(t *testing.T) {
			t.Parallel()
			errs := validateWitnessFile(path)
			for _, e := range errs {
				t.Errorf("%s: %s", path, e)
			}
		})
	}
}
