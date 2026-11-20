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
	"io"
	"os"
	"sort"
	"strings"

	"github.com/google/google-tlog-witness/internal/flagutil"
)

// The roles a tlog-policy can be generated for.
const (
	roleLog      = "log"
	roleVerifier = "verifier"
)

// roleGroupPrefix starts the keyword of a role-qualified group line: it is
// followed by the role the line applies to.
const roleGroupPrefix = "group-"

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
	if *role != roleLog && *role != roleVerifier {
		return fmt.Errorf("--role must be %q or %q, got %q", roleLog, roleVerifier, *role)
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
	witnessCfg := sectionConfig{kind: "witness", allowWitness: true}
	for _, path := range *witnesses {
		content, err := readSection(path, *role, witnessCfg, definedNames)
		if err != nil {
			return fmt.Errorf("processing witness file %s: %v", path, err)
		}
		output = append(output, "")
		output = append(output, fmt.Sprintf("# Witnesses from %s", path))
		output = append(output, content...)
	}

	// Process the policy file: inline its group and quorum rules, resolving
	// role-qualified groups and validating references against definedNames.
	policyCfg := sectionConfig{kind: "policy", requireQuorum: true}
	policyLines, err := readSection(*policyFile, *role, policyCfg, definedNames)
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

// sectionConfig controls which keywords are permitted in an input section file.
type sectionConfig struct {
	kind          string // "witness" or "policy", used in error messages
	allowWitness  bool
	requireQuorum bool
}

// readSection reads a witness or policy file at path. See resolveSection.
func readSection(path, role string, cfg sectionConfig, definedNames map[string]bool) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return resolveSection(f, role, cfg, definedNames)
}

// resolveSection reads a witness or policy file and returns the lines to inline
// into a policy for the given role (preserving comments), recording newly
// defined witness and group names in definedNames.
//
// A group can be defined differently for the log and for verifiers by a pair
// of "group-log" and "group-verifier" lines sharing a name. The line for role
// is returned as a plain "group" line, and the other is left out. Each such
// name needs exactly one line for each role, and is added to definedNames once
// both have appeared.
func resolveSection(r io.Reader, role string, cfg sectionConfig, definedNames map[string]bool) ([]string, error) {
	// The roles for which each role-qualified group has a line so far.
	roleGroups := make(map[string]map[string]bool)

	var lines []string
	quorumCount := 0

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()

		trimmed := strings.TrimSpace(line)
		fields := strings.Fields(trimmed)
		if len(fields) == 0 || strings.HasPrefix(trimmed, "#") {
			lines = append(lines, line)
			continue
		}

		switch keyword := fields[0]; keyword {
		case "witness":
			if !cfg.allowWitness {
				return nil, fmt.Errorf("%s files must not contain %q lines", cfg.kind, keyword)
			}
			if len(fields) < 3 {
				return nil, fmt.Errorf("invalid witness line: %q", trimmed)
			}
			name := fields[1]
			if definedNames[name] || roleGroups[name] != nil {
				return nil, fmt.Errorf("duplicate name %q", name)
			}
			definedNames[name] = true
		case "group":
			if len(fields) < 4 {
				return nil, fmt.Errorf("invalid group line: %q", trimmed)
			}
			name := fields[1]
			if definedNames[name] || roleGroups[name] != nil {
				return nil, fmt.Errorf("duplicate name %q", name)
			}
			for _, member := range fields[3:] {
				if !definedNames[member] {
					return nil, fmt.Errorf("group %q references undefined name %q", name, member)
				}
			}
			definedNames[name] = true
		case roleGroupPrefix + roleLog, roleGroupPrefix + roleVerifier:
			if len(fields) < 4 {
				return nil, fmt.Errorf("invalid %s line: %q", keyword, trimmed)
			}
			name := fields[1]
			if definedNames[name] {
				return nil, fmt.Errorf("duplicate name %q", name)
			}
			lineRole := strings.TrimPrefix(keyword, roleGroupPrefix)
			if roleGroups[name] == nil {
				roleGroups[name] = make(map[string]bool)
			}
			if roleGroups[name][lineRole] {
				return nil, fmt.Errorf("more than one %s line for %q", keyword, name)
			}
			for _, member := range fields[3:] {
				if !definedNames[member] {
					return nil, fmt.Errorf("group %q references undefined name %q", name, member)
				}
			}
			roleGroups[name][lineRole] = true
			if roleGroups[name][roleLog] && roleGroups[name][roleVerifier] {
				definedNames[name] = true
			}
			if lineRole != role {
				continue
			}
			// Rewrite the keyword, dropping any padding that aligned the pair
			// of lines with each other.
			i := strings.Index(line, keyword)
			line = line[:i] + "group " + strings.TrimLeft(line[i+len(keyword):], " \t")
		case "quorum":
			if !cfg.requireQuorum {
				return nil, fmt.Errorf("%s files must not contain %q lines", cfg.kind, keyword)
			}
			if len(fields) != 2 {
				return nil, fmt.Errorf("invalid quorum line: %q", trimmed)
			}
			quorumCount++
			if quorumCount > 1 {
				return nil, fmt.Errorf("%s file must contain at most one quorum line", cfg.kind)
			}
			q := fields[1]
			if q != "none" && !definedNames[q] {
				return nil, fmt.Errorf("quorum references undefined name %q", q)
			}
		case "log":
			return nil, fmt.Errorf("%s files must not contain %q lines", cfg.kind, keyword)
		default:
			return nil, fmt.Errorf("unrecognised keyword %q in %s file", keyword, cfg.kind)
		}
		lines = append(lines, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	var unpaired []string
	for name, roles := range roleGroups {
		if !roles[roleLog] || !roles[roleVerifier] {
			unpaired = append(unpaired, name)
		}
	}
	if len(unpaired) > 0 {
		sort.Strings(unpaired)
		return nil, fmt.Errorf("groups need both a %s and a %s line: %s",
			roleGroupPrefix+roleLog, roleGroupPrefix+roleVerifier, strings.Join(unpaired, ", "))
	}
	if cfg.requireQuorum && quorumCount == 0 {
		return nil, fmt.Errorf("%s file must contain a quorum line", cfg.kind)
	}

	for len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) == "" {
		lines = lines[:len(lines)-1]
	}

	return lines, nil
}
