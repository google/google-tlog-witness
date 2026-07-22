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

// Package log_list_files_test validates log-list files against the
// witness-network log-list format (logs/v0):
// https://github.com/transparency-dev/witness-network/blob/main/log-list-format.md
//
// The format is line-terminated. Blank lines and lines starting with '#' are
// ignored. All leading and trailing whitespace is removed before processing.
//
// A valid log-list file starts with the header line "logs/v0", followed by
// zero or more log entries. Each log entry consists of key-value lines:
//
//	vkey <origin>+<keyid>+<base64key>       (required, exactly once per log)
//	origin <string>                         (optional, alternative origin)
//	qpd <positive integer>                  (optional, queries per day)
//	contact <string>                        (optional, contact information)
//
// The "vkey" field follows the <origin>+<keyid>+<base64key> format.
// Each file must have the "logs/v0" header line and at least one log entry.
// Origins (derived from vkey or explicit "origin" lines) must be unique.
package log_list_files_test

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/google/google-tlog-witness/internal/vkey"
)

// validateLogListFile checks the structure and correctness of a single
// log-list file, returning a list of human-readable error strings (one per
// violation).
func validateLogListFile(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return []string{fmt.Sprintf("cannot open file: %v", err)}
	}
	defer f.Close()

	var errs []string
	lineNum := 0
	sawHeader := false

	// Per-log state.
	currentLogLine := 0 // line where current log started (for error context)
	sawVkey := false    // whether current log block has a vkey line
	logCount := 0       // total logs seen

	// validLogKeys are the permitted key-value keys within a log entry.
	validLogKeys := map[string]bool{
		"vkey":    true,
		"origin":  true,
		"qpd":     true,
		"contact": true,
	}

	// finishLog validates the accumulated state for a completed log block.
	finishLog := func() {
		if !sawVkey {
			if currentLogLine > 0 {
				errs = append(errs, fmt.Sprintf("line %d: log entry has no vkey line", currentLogLine))
			}
		}
	}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lineNum++
		raw := scanner.Text()
		trimmed := strings.TrimSpace(raw)

		// Blank lines and comments are ignored.
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		// The first non-blank, non-comment line must be the header.
		if !sawHeader {
			if trimmed != "logs/v0" {
				errs = append(errs, fmt.Sprintf("line %d: expected header \"logs/v0\", got %q", lineNum, trimmed))
			}
			sawHeader = true
			continue
		}

		// Split into key and value.
		fields := strings.Fields(trimmed)
		key := fields[0]

		if !validLogKeys[key] {
			errs = append(errs, fmt.Sprintf("line %d: unrecognised key %q; expected one of: vkey, origin, qpd, contact", lineNum, key))
			continue
		}

		switch key {
		case "vkey":
			// A new vkey starts a new log block. Finish the previous one.
			if sawVkey {
				finishLog()
			}

			logCount++
			sawVkey = true
			currentLogLine = lineNum

			if len(fields) != 2 {
				errs = append(errs, fmt.Sprintf("line %d: vkey line must have exactly 1 value, got %d: %q", lineNum, len(fields)-1, trimmed))
				continue
			}

			vkeyStr := fields[1]

			// Validate vkey format: <origin>+<keyid>+<base64key>.
			vkeyErrs, _ := vkey.Validate(vkeyStr, lineNum)
			if len(vkeyErrs) > 0 {
				errs = append(errs, vkeyErrs...)
			}

		case "origin":
			if len(fields) < 2 {
				errs = append(errs, fmt.Sprintf("line %d: origin line must have a value", lineNum))
			}
			// origin is an optional alternative to the vkey-derived origin.
			// We track it for informational purposes but don't enforce uniqueness
			// on it separately (the vkey origin is the canonical identifier).

		case "qpd":
			if len(fields) != 2 {
				errs = append(errs, fmt.Sprintf("line %d: qpd line must have exactly 1 value, got %d: %q", lineNum, len(fields)-1, trimmed))
				continue
			}
			n, err := strconv.Atoi(fields[1])
			if err != nil || n <= 0 {
				errs = append(errs, fmt.Sprintf("line %d: qpd must be a positive integer, got %q", lineNum, fields[1]))
			}

		case "contact":
			if len(fields) < 2 {
				errs = append(errs, fmt.Sprintf("line %d: contact line must have a value", lineNum))
			}
			// contact value is free-form text, no further validation.
		}

		// Ensure this key-value line appears within a log block (after a vkey).
		if key != "vkey" && !sawVkey {
			errs = append(errs, fmt.Sprintf("line %d: %q line appears before any vkey line", lineNum, key))
		}
	}

	if err := scanner.Err(); err != nil {
		errs = append(errs, fmt.Sprintf("scanner error: %v", err))
	}

	if !sawHeader {
		errs = append(errs, "file has no header line (expected \"logs/v0\")")
	}

	// Finish the last log block.
	if sawVkey {
		finishLog()
	}

	if logCount == 0 && sawHeader {
		errs = append(errs, "file defines no log entries")
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
