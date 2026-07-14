// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package tlog_policy_files_test validates tlog-policy files against the
// specification at https://c2sp.org/tlog-policy.
//
// The format is line based. Blank lines and lines starting with '#' (preceded
// by optional whitespace) are ignored. The supported line types are:
//
//	log <vkey> [<url>]
//	witness <name> <vkey> [<url>]
//	group <name> <threshold|any|all> <member>...
//	quorum <name>
//
// Structural requirements:
//   - There must be exactly one "quorum" line.
//   - Group members must reference previously-defined names.
//   - The quorum must reference a previously-defined name (or "none").
//   - No duplicate log vkeys.
//   - No duplicate witness/group names (they share a namespace).
//   - If a numeric threshold is given for a group, 1 <= k <= n.
package tlog_policy_files_test

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/google/google-tlog-witness/internal/vkey"
)

// validateTlogPolicyFile checks the structure and correctness of a single
// tlog-policy file, returning a list of human-readable error strings (one per
// violation).
func validateTlogPolicyFile(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return []string{fmt.Sprintf("cannot open file: %v", err)}
	}
	defer f.Close()

	var errs []string
	lineNum := 0
	quorumCount := 0

	// Namespace for witnesses and groups.
	definedNames := make(map[string]bool)
	// Track log vkeys for duplicate detection.
	logVkeys := make(map[string]int) // vkey string -> line number

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lineNum++
		raw := scanner.Text()
		trimmed := strings.TrimSpace(raw)

		// Blank lines and comments are ignored.
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		fields := strings.Fields(trimmed)
		keyword := fields[0]

		switch keyword {
		case "log":
			// log <vkey> [<url>]
			if len(fields) < 2 || len(fields) > 3 {
				errs = append(errs, fmt.Sprintf("line %d: log line must have 2 or 3 fields, got %d: %q", lineNum, len(fields), trimmed))
				continue
			}
			vkeyStr := fields[1]

			// Validate vkey format.
			if vkeyErrs, _ := vkey.Validate(vkeyStr, lineNum); len(vkeyErrs) > 0 {
				errs = append(errs, vkeyErrs...)
			}

			// Check for duplicate log vkeys.
			if prev, exists := logVkeys[vkeyStr]; exists {
				errs = append(errs, fmt.Sprintf("line %d: duplicate log vkey (first seen on line %d)", lineNum, prev))
			} else {
				logVkeys[vkeyStr] = lineNum
			}

			// Validate optional URL.
			if len(fields) == 3 {
				if u, err := url.Parse(fields[2]); err != nil || u.Scheme == "" || u.Host == "" {
					errs = append(errs, fmt.Sprintf("line %d: invalid log URL %q", lineNum, fields[2]))
				}
			}

		case "witness":
			// witness <name> <vkey> [<url>]
			if len(fields) < 3 || len(fields) > 4 {
				errs = append(errs, fmt.Sprintf("line %d: witness line must have 3 or 4 fields, got %d: %q", lineNum, len(fields), trimmed))
				continue
			}
			name := fields[1]
			vkeyStr := fields[2]

			// Validate name uniqueness.
			if definedNames[name] {
				errs = append(errs, fmt.Sprintf("line %d: duplicate name %q", lineNum, name))
			} else {
				definedNames[name] = true
			}

			// Validate vkey format.
			if vkeyErrs, _ := vkey.Validate(vkeyStr, lineNum); len(vkeyErrs) > 0 {
				errs = append(errs, vkeyErrs...)
			}

			// Validate optional URL.
			if len(fields) == 4 {
				if u, err := url.Parse(fields[3]); err != nil || u.Scheme == "" || u.Host == "" {
					errs = append(errs, fmt.Sprintf("line %d: invalid witness URL %q", lineNum, fields[3]))
				}
			}

		case "group":
			// group <name> <threshold|any|all> <member>...
			if len(fields) < 4 {
				errs = append(errs, fmt.Sprintf("line %d: group line must have at least 4 fields, got %d: %q", lineNum, len(fields), trimmed))
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
			n := len(members)
			switch threshold {
			case "any", "all":
				// Valid.
			default:
				k, err := strconv.Atoi(threshold)
				if err != nil || k < 1 || k > n {
					errs = append(errs, fmt.Sprintf("line %d: group threshold must be \"any\", \"all\", or an integer 1 <= k <= %d, got %q", lineNum, n, threshold))
				}
			}

			// Validate that all members reference previously-defined names.
			seen := make(map[string]bool)
			for _, member := range members {
				if member == "none" {
					errs = append(errs, fmt.Sprintf("line %d: group %q: \"none\" is not valid as a group member", lineNum, name))
				} else if !definedNames[member] {
					errs = append(errs, fmt.Sprintf("line %d: group %q references undefined name %q", lineNum, name, member))
				}
				if seen[member] {
					errs = append(errs, fmt.Sprintf("line %d: group %q lists member %q more than once", lineNum, name, member))
				}
				seen[member] = true
			}

		case "quorum":
			// quorum <name>
			if len(fields) != 2 {
				errs = append(errs, fmt.Sprintf("line %d: quorum line must have exactly 2 fields, got %d: %q", lineNum, len(fields), trimmed))
				continue
			}
			quorumCount++
			name := fields[1]
			if name != "none" && !definedNames[name] {
				errs = append(errs, fmt.Sprintf("line %d: quorum references undefined name %q", lineNum, name))
			}

		default:
			errs = append(errs, fmt.Sprintf("line %d: unrecognised keyword %q", lineNum, keyword))
		}
	}

	if err := scanner.Err(); err != nil {
		errs = append(errs, fmt.Sprintf("scanner error: %v", err))
	}

	if quorumCount == 0 {
		errs = append(errs, "file has no quorum line")
	} else if quorumCount > 1 {
		errs = append(errs, fmt.Sprintf("file has %d quorum lines (expected exactly 1)", quorumCount))
	}

	return errs
}

// TestTlogPolicyFiles validates every .policy file provided as test data.
func TestTlogPolicyFiles(t *testing.T) {
	matches, err := filepath.Glob("*.policy")
	if err != nil {
		t.Fatalf("globbing for *.policy: %v", err)
	}
	if len(matches) == 0 {
		t.Fatal("no .policy files found — check the test data / working directory")
	}

	for _, path := range matches {
		t.Run(strings.TrimSuffix(path, ".policy"), func(t *testing.T) {
			t.Parallel()
			errs := validateTlogPolicyFile(path)
			for _, e := range errs {
				t.Errorf("%s: %s", path, e)
			}
		})
	}
}
