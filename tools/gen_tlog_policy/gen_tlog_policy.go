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

// gen_tlog_policy generates a tlog-policy file by inlining log-list, witness,
// and policy configuration inputs.
//
// The output format follows the tlog-policy specification:
// https://c2sp.org/tlog-policy
//
// The generated file is structured as follows:
//   - For each log-list input: a header comment identifying the source,
//     followed by "log <vkey>" lines extracted from the file.
//   - For each witness input: a header comment identifying the source,
//     followed by the file contents inlined. Role-qualified group lines
//     ("group-log" and "group-verifier") are resolved for --role: the line
//     for that role is emitted as a plain "group" line and the line for the
//     other role is dropped, so the output is always a standard tlog-policy.
//   - For the policy input: a header comment identifying the source, followed
//     by the file's group definitions (with any role-qualified group lines
//     resolved for --role) and its quorum rule.
//
// Usage:
//
//	gen_tlog_policy --role=<log|verifier>
//	    --log-list=<path> [--log-list=<path>...]
//	    --witnesses=<path> [--witnesses=<path>...]
//	    --policy=<path>
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/google/google-tlog-witness/internal/flagutil"
	"github.com/google/google-tlog-witness/internal/section"
)

var (
	role       = flag.String("role", "", "who consumes the policy: \"log\" or \"verifier\" (required)")
	logLists   = flagutil.StringSlice("log-list", "path to a log-list file (repeatable)")
	witnesses  = flagutil.StringSlice("witnesses", "path to a witness config file (repeatable)")
	policyFile = flag.String("policy", "", "path to a policy file containing group and quorum rules (required)")
)

func main() {
	flag.Parse()

	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	if *role != section.RoleLog && *role != section.RoleVerifier {
		return fmt.Errorf("--role must be %q or %q, got %q", section.RoleLog, section.RoleVerifier, *role)
	}
	if len(*logLists) == 0 {
		return fmt.Errorf("at least one --log-list is required")
	}
	if *policyFile == "" {
		return fmt.Errorf("--policy is required")
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

	// Process witness files: inline them, resolving role-qualified groups and
	// recording defined names for validation.
	for _, path := range *witnesses {
		content, err := section.ResolveFile(path, *role, section.Witnesses, definedNames)
		if err != nil {
			return fmt.Errorf("processing witness file %s: %v", path, err)
		}
		output = append(output, "")
		output = append(output, fmt.Sprintf("# Witnesses from %s", path))
		output = append(output, content...)
	}

	// Process the policy file: inline its group and quorum rules, resolving
	// role-qualified groups and validating references against definedNames.
	policyLines, err := section.ResolveFile(*policyFile, *role, section.Policy, definedNames)
	if err != nil {
		return fmt.Errorf("processing policy file %s: %v", *policyFile, err)
	}

	output = append(output, "")
	output = append(output, fmt.Sprintf("# Policy from %s", *policyFile))
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
