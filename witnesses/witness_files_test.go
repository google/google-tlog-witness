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

// Package witnesses_test validates all witness config files in the witnesses/
// directory against the tlog-policy witness file format:
//
//	# Comments start with '#'; blank lines are ignored.
//	witness <name> <vkey> [<url>]
//	group <name> <threshold|any|all> <member>...
//	group-log <name> <threshold|any|all> <member>...
//	group-verifier <name> <threshold|any|all> <member>...
//
// "log" and "quorum" lines are not permitted.
// Each file must define at least one witness.
// Names (witness and group) must be unique within a file.
// Group members must reference names defined earlier in the same file.
// A "group-log" and a "group-verifier" line sharing a name define one group
// differently for the log policy and the verifier policy. Each such name must
// have exactly one line of each kind, and is defined once both have appeared.
// The vkey field of a witness line must follow the <name>+<keyid>+<key> format.
// The URL field of a witness line is required.
package witnesses_test

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
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
	// For each group defined by role-qualified lines, the keywords ("group-log",
	// "group-verifier") seen for it so far.
	roleGroups := make(map[string]map[string]bool)
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

			// Validate vkey format and witness key type.
			if vkeyStr != "" {
				if vkeyErrs, _ := vkey.ValidateWitness(vkeyStr, lineNum); len(vkeyErrs) > 0 {
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

		case "group", "group-log", "group-verifier":
			// group <name> <threshold|any|all> <member>...
			// Minimum: keyword + name + threshold + one member = 4 fields.
			if len(fields) < 4 {
				errs = append(errs, fmt.Sprintf("line %d: %s line must have at least 4 fields (keyword name threshold member...), got %d: %q", lineNum, keyword, len(fields), trimmed))
				continue
			}
			name := fields[1]
			threshold := fields[2]
			members := fields[3:]

			// Validate name uniqueness. A role-qualified group takes two lines
			// to define, one per role, so its name only becomes defined (below)
			// once both have been seen.
			roleQualified := keyword != "group"
			switch {
			case roleQualified && roleGroups[name][keyword]:
				errs = append(errs, fmt.Sprintf("line %d: more than one %s line for %q", lineNum, keyword, name))
			case definedNames[name] || (!roleQualified && roleGroups[name] != nil):
				errs = append(errs, fmt.Sprintf("line %d: duplicate name %q", lineNum, name))
			case roleQualified:
				if roleGroups[name] == nil {
					roleGroups[name] = make(map[string]bool)
				}
				roleGroups[name][keyword] = true
			default:
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

			if roleGroups[name]["group-log"] && roleGroups[name]["group-verifier"] {
				definedNames[name] = true
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

	var unpaired []string
	for name, keywords := range roleGroups {
		if !keywords["group-log"] || !keywords["group-verifier"] {
			unpaired = append(unpaired, name)
		}
	}
	sort.Strings(unpaired)
	for _, name := range unpaired {
		errs = append(errs, fmt.Sprintf("group %q needs both a group-log and a group-verifier line", name))
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

// TestValidateWitnessFileRoleGroups checks the rules for groups defined by a
// pair of "group-log" and "group-verifier" lines.
func TestValidateWitnessFileRoleGroups(t *testing.T) {
	// An Ed25519 cosignature vkey with a fixed key body. The key ID is not
	// recomputed; nothing under test verifies it.
	vkey := "w.example+deadbeef+" + base64.StdEncoding.EncodeToString(append([]byte{0x04}, make([]byte, 32)...))
	witnesses := "witness w-old " + vkey + " https://w.example\n" +
		"witness w-new " + vkey + " https://w.example\n"

	for _, tc := range []struct {
		name    string
		groups  string
		wantErr string // empty if the file is valid
	}{
		{
			name:   "pair",
			groups: "group-log w all w-old w-new\ngroup-verifier w any w-old\ngroup operator any w\n",
		},
		{
			name:   "pair in either order",
			groups: "group-verifier w any w-old\ngroup-log w all w-old w-new\n",
		},
		{
			name:    "group-log alone",
			groups:  "group-log w all w-old w-new\n",
			wantErr: `group "w" needs both a group-log and a group-verifier line`,
		},
		{
			name:    "group-verifier alone",
			groups:  "group-verifier w any w-old\n",
			wantErr: `group "w" needs both a group-log and a group-verifier line`,
		},
		{
			name:    "repeated group-log",
			groups:  "group-log w all w-old\ngroup-log w all w-new\ngroup-verifier w any w-old\n",
			wantErr: `more than one group-log line for "w"`,
		},
		{
			name:    "name shared with a witness",
			groups:  "group-log w-old all w-new\ngroup-verifier w-old all w-new\n",
			wantErr: `duplicate name "w-old"`,
		},
		{
			name:    "name shared with an earlier plain group",
			groups:  "group w any w-old\ngroup-log w all w-old\ngroup-verifier w all w-new\n",
			wantErr: `duplicate name "w"`,
		},
		{
			name:    "name shared with a later plain group",
			groups:  "group-log w all w-old\ngroup w any w-new\ngroup-verifier w all w-old\n",
			wantErr: `duplicate name "w"`,
		},
		{
			name:    "used as a member before both lines",
			groups:  "group-log w all w-old\ngroup operator any w\ngroup-verifier w all w-old\n",
			wantErr: `group "operator" references undefined name "w"`,
		},
		{
			name:    "undefined member",
			groups:  "group-log w all w-old\ngroup-verifier w all nobody\n",
			wantErr: `group "w" references undefined name "nobody"`,
		},
		{
			name:    "no members",
			groups:  "group-log w all\ngroup-verifier w all w-old\n",
			wantErr: "group-log line must have at least 4 fields",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "witness.txt")
			if err := os.WriteFile(path, []byte(witnesses+tc.groups), 0o644); err != nil {
				t.Fatal(err)
			}
			errs := validateWitnessFile(path)
			if tc.wantErr == "" {
				if len(errs) > 0 {
					t.Errorf("validateWitnessFile() errors: %q, want none", errs)
				}
				return
			}
			if !strings.Contains(strings.Join(errs, "\n"), tc.wantErr) {
				t.Errorf("validateWitnessFile() errors: %q, want one containing %q", errs, tc.wantErr)
			}
		})
	}
}
