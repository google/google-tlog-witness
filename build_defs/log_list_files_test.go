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

// Package log_list_files_test validates log-list files against
// https://c2sp.org/tlog-list, with the following deviations:
//
//   - The spec permits only one vkey per log, but our logs publish several
//     keys (e.g. Ed25519 and ML-DSA-44). Consecutive entries that share an
//     origin are therefore accepted as keys of the same log, provided they
//     agree on qpd and contact. Entries sharing an origin must be adjacent.
//   - The spec permits a list with zero logs. We require at least one, since
//     an empty product list is almost certainly a mistake.
package log_list_files_test

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/google/google-tlog-witness/internal/vkey"
)

// qpdRe matches an ASCII decimal with no sign and no leading zeroes.
var qpdRe = regexp.MustCompile(`^[1-9][0-9]*$`)

// maxQPD is the exclusive upper bound on qpd values.
const maxQPD = 1 << 31

// nextKeys maps the previous key-value key within a log entry to the keys
// that may follow it. The empty string represents "no current entry".
var nextKeys = map[string][]string{
	"":        {"vkey"},
	"vkey":    {"origin", "qpd"},
	"origin":  {"qpd"},
	"qpd":     {"contact"},
	"contact": {"vkey"},
}

// logEntry holds the key-value lines of a single log entry (one vkey).
type logEntry struct {
	line    int // line of the vkey line
	keyName string
	vkey    string
	origin  string  // value of the origin line, or "" if omitted
	qpd     *string // nil if the qpd line is missing
	contact *string // nil if the contact line is missing
}

// effectiveOrigin returns the entry's origin line, defaulting to the vkey's
// key name.
func (e *logEntry) effectiveOrigin() string {
	if e.origin != "" {
		return e.origin
	}
	return e.keyName
}

// splitKeyValue splits a trimmed line into its key and value at the first
// space or tab. The value has leading space and tab characters removed.
func splitKeyValue(line string) (key, value string) {
	i := strings.IndexAny(line, " \t")
	if i < 0 {
		return line, ""
	}
	return line[:i], strings.TrimLeft(line[i+1:], " \t")
}

// validateLogListFile checks the structure and correctness of a single
// log-list file, returning a list of human-readable error strings (one per
// violation).
func validateLogListFile(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return []string{fmt.Sprintf("cannot read file: %v", err)}
	}
	return validateLogList(string(data))
}

// validateLogList checks the contents of a log-list file, returning a list of
// human-readable error strings (one per violation).
func validateLogList(data string) []string {
	var errs []string
	addErr := func(format string, args ...any) {
		errs = append(errs, fmt.Sprintf(format, args...))
	}

	sawHeader := false
	var entries []*logEntry
	var cur *logEntry // current log entry, nil before the first vkey
	prevKey := ""     // previous key within cur, "" if none

	// finishEntry reports any required lines missing from cur.
	finishEntry := func() {
		if cur == nil {
			return
		}
		var missing []string
		if cur.qpd == nil {
			missing = append(missing, "qpd")
		}
		if cur.contact == nil {
			missing = append(missing, "contact")
		}
		if len(missing) > 0 {
			addErr("line %d: log entry is missing required %s line(s)", cur.line, strings.Join(missing, " and "))
		}
	}

	for i, raw := range strings.Split(data, "\n") {
		lineNum := i + 1

		// Only LF separates lines; a CR would otherwise silently become part
		// of the value.
		if strings.ContainsRune(raw, '\r') {
			addErr("line %d: contains a carriage return; lines must be separated by LF (0x0A) only", lineNum)
			continue
		}

		line := strings.Trim(raw, " \t")

		// Blank lines and comments are ignored.
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// The first non-blank, non-comment line must be the header.
		if !sawHeader {
			if line != "logs/v0" {
				addErr("line %d: expected header \"logs/v0\", got %q", lineNum, line)
			}
			sawHeader = true
			continue
		}

		key, value := splitKeyValue(line)
		if _, known := nextKeys[key]; !known || key == "" {
			addErr("line %d: unrecognised key %q; expected one of: vkey, origin, qpd, contact", lineNum, key)
			continue
		}

		// Enforce the fixed order vkey, [origin], qpd, contact.
		inOrder := false
		for _, k := range nextKeys[prevKey] {
			if k == key {
				inOrder = true
				break
			}
		}
		if !inOrder {
			addErr("line %d: unexpected %q line; expected %s (log entries must be: vkey, [origin], qpd, contact)",
				lineNum, key, strings.Join(nextKeys[prevKey], " or "))
		}

		if key == "vkey" {
			finishEntry()
			cur = &logEntry{line: lineNum}
			entries = append(entries, cur)
		} else if cur == nil {
			addErr("line %d: %q line appears before any vkey line", lineNum, key)
			continue
		}
		prevKey = key

		switch key {
		case "vkey":
			if value == "" || strings.ContainsAny(value, " \t") {
				addErr("line %d: vkey line must have exactly 1 value: %q", lineNum, line)
				continue
			}
			vkeyErrs, name := vkey.Validate(value, lineNum)
			errs = append(errs, vkeyErrs...)
			cur.vkey = value
			cur.keyName = name

		case "origin":
			if value == "" {
				addErr("line %d: origin line must have a value", lineNum)
			}
			cur.origin = value

		case "qpd":
			cur.qpd = &value
			if !qpdRe.MatchString(value) {
				addErr("line %d: qpd must be an ASCII decimal with no sign or leading zeroes, got %q", lineNum, value)
			} else if n, err := strconv.ParseInt(value, 10, 64); err != nil || n >= maxQPD {
				addErr("line %d: qpd must be in the range [1, 2^31), got %q", lineNum, value)
			}

		case "contact":
			cur.contact = &value
			if value == "" {
				addErr("line %d: contact line must have a value", lineNum)
			}
		}
	}

	finishEntry()

	if !sawHeader {
		addErr("file has no header line (expected \"logs/v0\")")
	} else if len(entries) == 0 {
		addErr("file defines no log entries")
	}

	errs = append(errs, checkOrigins(entries)...)
	return errs
}

// checkOrigins checks that no two logs share an origin, and that no vkey is
// listed twice.
//
// TODO(benbirt): c2sp.org/tlog-list allows only one vkey per log ("Each log
// can have only one vkey"), and "Two logs MUST NOT share the same origin".
// We currently relax this by treating adjacent entries with the same origin
// as multiple keys of one log. Once it is possible to publish a single vkey
// per log (e.g. the spec gains multi-key support, or our logs drop to one
// key each), remove the adjacency grouping below and reject any repeated
// origin outright.
func checkOrigins(entries []*logEntry) []string {
	var errs []string
	seenVkeys := make(map[string]int)   // vkey -> line of first occurrence
	seenOrigins := make(map[string]int) // origin -> line of first entry of its log
	var prev *logEntry

	for _, e := range entries {
		if e.vkey != "" {
			if first, ok := seenVkeys[e.vkey]; ok {
				errs = append(errs, fmt.Sprintf("line %d: vkey %q is already listed at line %d", e.line, e.vkey, first))
			} else {
				seenVkeys[e.vkey] = e.line
			}
		}

		origin := e.effectiveOrigin()
		if origin == "" {
			// The vkey was malformed; that has already been reported.
			prev = nil
			continue
		}

		switch first, seen := seenOrigins[origin]; {
		case prev != nil && prev.effectiveOrigin() == origin:
			// An additional key for the same log (see TODO above). The log's
			// parameters must be consistent across its keys.
			// Missing lines have already been reported.
			if e.qpd != nil && prev.qpd != nil && *e.qpd != *prev.qpd {
				errs = append(errs, fmt.Sprintf("line %d: qpd %q differs from qpd %q of the preceding key for origin %q", e.line, *e.qpd, *prev.qpd, origin))
			}
			if e.contact != nil && prev.contact != nil && *e.contact != *prev.contact {
				errs = append(errs, fmt.Sprintf("line %d: contact %q differs from contact %q of the preceding key for origin %q", e.line, *e.contact, *prev.contact, origin))
			}
		case seen:
			errs = append(errs, fmt.Sprintf("line %d: origin %q is already used by the log at line %d; logs must not share an origin", e.line, origin, first))
		default:
			seenOrigins[origin] = e.line
		}
		prev = e
	}
	return errs
}

// TestLogListFiles validates every .txt file provided as test data.
func TestLogListFiles(t *testing.T) {
	// Under Bazel the test binary runs with the package source directory as
	// cwd (via runfiles), so "." is the package dir. When the macro is used,
	// the data files are provided as glob results and resolve from ".".
	matches, err := filepath.Glob("*.txt")
	if err != nil {
		t.Fatalf("globbing for *.txt: %v", err)
	}
	if len(matches) == 0 {
		t.Fatal("no .txt files found — check the test data / working directory")
	}

	for _, path := range matches {
		path := path // capture
		t.Run(strings.TrimSuffix(path, ".txt"), func(t *testing.T) {
			t.Parallel()
			errs := validateLogListFile(path)
			for _, e := range errs {
				t.Errorf("%s: %s", path, e)
			}
		})
	}
}

// testVkey returns a syntactically valid vkey with the given key name. The
// key ID is not derived from the key, which vkey.Validate does not check.
func testVkey(name string) string {
	return name + "+01234567+AQ" + strings.Repeat("A", 42)
}

// TestValidateLogList exercises the validator itself.
func TestValidateLogList(t *testing.T) {
	a, a2, b := testVkey("a.example/log"), "a.example/log+89abcdef+Bg"+strings.Repeat("A", 42), testVkey("b.example/log")

	for _, tc := range []struct {
		name    string
		data    string
		wantErr string // substring of the expected error, or "" for valid input
	}{
		{
			name: "valid",
			data: "# comment\nlogs/v0\n\nvkey " + a + "\nqpd 86400\ncontact https://a.example/contact\n",
		},
		{
			name: "valid with origin and indentation",
			data: "logs/v0\nvkey " + a + "\norigin something-else\n\tqpd 24\n  contact sysadmin (at) a.example\n",
		},
		{
			name: "valid multiple logs",
			data: "logs/v0\nvkey " + a + "\nqpd 1\ncontact x\nvkey " + b + "\nqpd 2147483647\ncontact y\n",
		},
		{
			name: "valid multiple keys per log",
			data: "logs/v0\nvkey " + a + "\nqpd 10\ncontact x\nvkey " + a2 + "\nqpd 10\ncontact x\n",
		},
		{
			name:    "missing header",
			data:    "vkey " + a + "\nqpd 10\ncontact x\n",
			wantErr: `expected header "logs/v0"`,
		},
		{
			name:    "no logs",
			data:    "logs/v0\n",
			wantErr: "no log entries",
		},
		{
			name:    "missing qpd",
			data:    "logs/v0\nvkey " + a + "\ncontact x\n",
			wantErr: "missing required qpd line",
		},
		{
			name:    "missing contact",
			data:    "logs/v0\nvkey " + a + "\nqpd 10\n",
			wantErr: "missing required contact line",
		},
		{
			name:    "contact before qpd",
			data:    "logs/v0\nvkey " + a + "\ncontact x\nqpd 10\n",
			wantErr: `unexpected "contact" line`,
		},
		{
			name:    "origin after qpd",
			data:    "logs/v0\nvkey " + a + "\nqpd 10\norigin o\ncontact x\n",
			wantErr: `unexpected "origin" line`,
		},
		{
			name:    "duplicate qpd",
			data:    "logs/v0\nvkey " + a + "\nqpd 10\nqpd 10\ncontact x\n",
			wantErr: `unexpected "qpd" line`,
		},
		{
			name:    "qpd before vkey",
			data:    "logs/v0\nqpd 10\n",
			wantErr: "before any vkey line",
		},
		{
			name:    "unknown key",
			data:    "logs/v0\nvkey " + a + "\nqpd 10\ncontact x\nfoo bar\n",
			wantErr: `unrecognised key "foo"`,
		},
		{
			name:    "qpd zero",
			data:    "logs/v0\nvkey " + a + "\nqpd 0\ncontact x\n",
			wantErr: "qpd must be an ASCII decimal",
		},
		{
			name:    "qpd leading zero",
			data:    "logs/v0\nvkey " + a + "\nqpd 010\ncontact x\n",
			wantErr: "qpd must be an ASCII decimal",
		},
		{
			name:    "qpd sign",
			data:    "logs/v0\nvkey " + a + "\nqpd +10\ncontact x\n",
			wantErr: "qpd must be an ASCII decimal",
		},
		{
			name:    "qpd too large",
			data:    "logs/v0\nvkey " + a + "\nqpd 2147483648\ncontact x\n",
			wantErr: "qpd must be in the range",
		},
		{
			name:    "empty contact",
			data:    "logs/v0\nvkey " + a + "\nqpd 10\ncontact\n",
			wantErr: "contact line must have a value",
		},
		{
			name:    "CRLF line endings",
			data:    "logs/v0\r\nvkey " + a + "\r\nqpd 10\r\ncontact x\r\n",
			wantErr: "carriage return",
		},
		{
			name:    "non-adjacent shared origin",
			data:    "logs/v0\nvkey " + a + "\nqpd 10\ncontact x\nvkey " + b + "\nqpd 10\ncontact x\nvkey " + a2 + "\nqpd 10\ncontact x\n",
			wantErr: `origin "a.example/log" is already used`,
		},
		{
			name:    "origin line collides with another log",
			data:    "logs/v0\nvkey " + a + "\nqpd 10\ncontact x\nvkey " + b + "\nqpd 10\ncontact x\nvkey " + testVkey("c.example/log") + "\norigin a.example/log\nqpd 10\ncontact x\n",
			wantErr: `origin "a.example/log" is already used`,
		},
		{
			name:    "multiple keys with different qpd",
			data:    "logs/v0\nvkey " + a + "\nqpd 10\ncontact x\nvkey " + a2 + "\nqpd 20\ncontact x\n",
			wantErr: "differs from qpd",
		},
		{
			name:    "multiple keys with different contact",
			data:    "logs/v0\nvkey " + a + "\nqpd 10\ncontact x\nvkey " + a2 + "\nqpd 10\ncontact y\n",
			wantErr: "differs from contact",
		},
		{
			name:    "duplicate vkey",
			data:    "logs/v0\nvkey " + a + "\nqpd 10\ncontact x\nvkey " + a + "\nqpd 10\ncontact x\n",
			wantErr: "is already listed",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			errs := validateLogList(tc.data)
			if tc.wantErr == "" {
				if len(errs) > 0 {
					t.Errorf("validateLogList() = %q, want no errors", errs)
				}
				return
			}
			for _, e := range errs {
				if strings.Contains(e, tc.wantErr) {
					return
				}
			}
			t.Errorf("validateLogList() = %q, want an error containing %q", errs, tc.wantErr)
		})
	}
}
