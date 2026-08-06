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

// gen_tlog_policy generates a tlog-policy file by inlining log-list and
// witness configuration inputs.
//
// The output format follows the tlog-policy specification:
// https://c2sp.org/tlog-policy
//
// The generated file is structured as follows:
//   - For each log-list input: a header comment identifying the source,
//     followed by "log <vkey>" lines extracted from the file.
//   - For each witness input: a header comment identifying the source,
//     followed by the file contents inlined verbatim.
//   - A "# Policy" section with any additional group definitions and
//     the quorum rule (both supplied via flags).
//
// Usage:
//
//	gen_tlog_policy --log-list=<path> [--log-list=<path>...]
//	    --witnesses=<path> [--witnesses=<path>...]
//	    [--group=<definition>...]
//	    --quorum=<name>
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/google/google-tlog-witness/internal/flagutil"
)

var (
	logLists  = flagutil.StringSlice("log-list", "path to a log-list file (repeatable)")
	witnesses = flagutil.StringSlice("witnesses", "path to a witness config file (repeatable)")
	groups    = flagutil.StringSlice("group", "additional group definition, e.g. 'group mygroup any w1 w2' (repeatable)")
	quorum    = flag.String("quorum", "", "quorum name (required)")
)

func main() {
	flag.Parse()

	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	if len(*logLists) == 0 {
		return fmt.Errorf("at least one --log-list is required")
	}
	if *quorum == "" {
		return fmt.Errorf("--quorum is required")
	}

	// Collect all output lines and defined names for validation.
	var output []string
	definedNames := make(map[string]bool)

	// Process log-list files.
	logCount := 0
	for i, path := range *logLists {
		vkeys, err := extractVkeys(path)
		if err != nil {
			return fmt.Errorf("processing log-list %s: %v", path, err)
		}

		if i > 0 {
			output = append(output, "")
		}
		output = append(output, fmt.Sprintf("# Log keys from %s", path))
		for _, vkey := range vkeys {
			output = append(output, fmt.Sprintf("log %s", vkey))
			logCount++
		}
	}

	if logCount == 0 {
		return fmt.Errorf("no log vkeys found in any log-list file")
	}

	// Process witness files: inline verbatim, extracting names for validation.
	for _, path := range *witnesses {
		content, names, err := readWitnessFile(path)
		if err != nil {
			return fmt.Errorf("processing witness file %s: %v", path, err)
		}
		for _, name := range names {
			if definedNames[name] {
				return fmt.Errorf("duplicate name %q in witness file %s", name, path)
			}
			definedNames[name] = true
		}
		output = append(output, "")
		output = append(output, fmt.Sprintf("# Witnesses from %s", path))
		output = append(output, content...)
	}

	// Process additional groups.
	var policyLines []string
	for _, g := range *groups {
		line := g
		if !strings.HasPrefix(line, "group ") {
			line = "group " + line
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			return fmt.Errorf("invalid group definition: %q (need at least 'group <name> <threshold> <member>')", g)
		}
		groupName := fields[1]
		if definedNames[groupName] {
			return fmt.Errorf("duplicate name %q in group definition", groupName)
		}
		definedNames[groupName] = true

		// Validate that group members reference defined names.
		for _, member := range fields[3:] {
			if !definedNames[member] {
				return fmt.Errorf("group %q references undefined name %q", groupName, member)
			}
		}
		policyLines = append(policyLines, line)
	}

	// Validate quorum reference.
	if *quorum != "none" && !definedNames[*quorum] {
		return fmt.Errorf("quorum references undefined name %q", *quorum)
	}

	policyLines = append(policyLines, fmt.Sprintf("quorum %s", *quorum))

	output = append(output, "")
	output = append(output, "# Policy")
	output = append(output, policyLines...)

	// Write output.
	for _, line := range output {
		fmt.Println(line)
	}
	return nil
}

// extractVkeys reads a log-list file and returns the vkey values.
func extractVkeys(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var vkeys []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "vkey ") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				vkeys = append(vkeys, fields[1])
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(vkeys) == 0 {
		return nil, fmt.Errorf("no vkey lines found")
	}
	return vkeys, nil
}

// readWitnessFile reads a witness config file and returns the lines to inline
// (preserving comments) and the names defined in the file (witness names and
// group names).
func readWitnessFile(path string) (lines []string, names []string, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		lines = append(lines, line)

		trimmed := strings.TrimSpace(line)
		fields := strings.Fields(trimmed)
		if len(fields) == 0 {
			continue
		}

		switch fields[0] {
		case "witness":
			if len(fields) < 3 {
				return nil, nil, fmt.Errorf("invalid witness line: %q", trimmed)
			}
			names = append(names, fields[1])
		case "group":
			if len(fields) < 4 {
				return nil, nil, fmt.Errorf("invalid group line: %q", trimmed)
			}
			names = append(names, fields[1])
		case "log", "quorum":
			return nil, nil, fmt.Errorf("witness files must not contain %q lines", fields[0])
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, err
	}

	// Trim trailing empty lines.
	for len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) == "" {
		lines = lines[:len(lines)-1]
	}

	return lines, names, nil
}
