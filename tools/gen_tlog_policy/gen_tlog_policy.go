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
	// extracting names for validation.
	for _, path := range *witnesses {
		content, names, err := readWitnessFile(path, *role)
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

	// Process the policy file: inline its group and quorum rules, resolving
	// role-qualified groups and validating references against definedNames.
	policyLines, err := readPolicyFile(*policyFile, *role, definedNames)
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

// readWitnessFile reads the witness config file at path. See
// resolveWitnessFile for what it returns.
func readWitnessFile(path, role string) (lines []string, names []string, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	return resolveWitnessFile(f, role)
}

// resolveWitnessFile reads a witness config file and returns the lines to
// inline into a policy for the given role (preserving comments) and the names
// defined in the file (witness names and group names).
//
// A group can be defined differently for the log and for verifiers by a pair
// of "group-log" and "group-verifier" lines sharing a name. The line for role
// is returned as a plain "group" line, and the other is left out. Each such
// name needs exactly one line for each role, so that the name is defined
// whichever role a policy is generated for.
func resolveWitnessFile(r io.Reader, role string) (lines []string, names []string, err error) {
	// The roles for which each role-qualified group has a line so far.
	roleGroups := make(map[string]map[string]bool)

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
			if len(fields) < 3 {
				return nil, nil, fmt.Errorf("invalid witness line: %q", trimmed)
			}
			names = append(names, fields[1])
		case "group":
			if len(fields) < 4 {
				return nil, nil, fmt.Errorf("invalid group line: %q", trimmed)
			}
			names = append(names, fields[1])
		case roleGroupPrefix + roleLog, roleGroupPrefix + roleVerifier:
			rewritten, name, emit, err := resolveRoleGroupLine(line, trimmed, fields, role, roleGroups)
			if err != nil {
				return nil, nil, err
			}
			if !emit {
				continue
			}
			names = append(names, name)
			line = rewritten
		case "log", "quorum":
			return nil, nil, fmt.Errorf("witness files must not contain %q lines", keyword)
		}
		lines = append(lines, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, err
	}

	if err := checkRoleGroupsPaired(roleGroups); err != nil {
		return nil, nil, err
	}

	return trimTrailingBlankLines(lines), names, nil
}

// readPolicyFile reads the policy file at path. See resolvePolicyFile for what
// it returns.
func readPolicyFile(path, role string, witnessNames map[string]bool) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return resolvePolicyFile(f, role, witnessNames)
}

// resolvePolicyFile reads a product policy file (containing group, group-log,
// group-verifier, and quorum lines) and returns the lines to inline into a
// policy for the given role (preserving comments).
//
// Group members may reference names in witnessNames or groups defined earlier
// in the policy file. A policy file must contain exactly one "quorum" line and
// must not contain "log" or "witness" lines.
func resolvePolicyFile(r io.Reader, role string, witnessNames map[string]bool) ([]string, error) {
	definedNames := make(map[string]bool, len(witnessNames))
	for name := range witnessNames {
		definedNames[name] = true
	}
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
		case "group":
			if len(fields) < 4 {
				return nil, fmt.Errorf("invalid group line: %q", trimmed)
			}
			name := fields[1]
			if definedNames[name] || roleGroups[name] != nil {
				return nil, fmt.Errorf("duplicate name %q in group definition", name)
			}
			for _, member := range fields[3:] {
				if !definedNames[member] {
					return nil, fmt.Errorf("group %q references undefined name %q", name, member)
				}
			}
			definedNames[name] = true
		case roleGroupPrefix + roleLog, roleGroupPrefix + roleVerifier:
			name := ""
			if len(fields) >= 2 {
				name = fields[1]
			}
			if name != "" && definedNames[name] {
				return nil, fmt.Errorf("duplicate name %q in %s definition", name, keyword)
			}
			rewritten, name, emit, err := resolveRoleGroupLine(line, trimmed, fields, role, roleGroups)
			if err != nil {
				return nil, err
			}
			for _, member := range fields[3:] {
				if !definedNames[member] {
					return nil, fmt.Errorf("group %q references undefined name %q", name, member)
				}
			}
			if roleGroups[name][roleLog] && roleGroups[name][roleVerifier] {
				definedNames[name] = true
			}
			if !emit {
				continue
			}
			line = rewritten
		case "quorum":
			if len(fields) != 2 {
				return nil, fmt.Errorf("invalid quorum line: %q", trimmed)
			}
			quorumCount++
			if quorumCount > 1 {
				return nil, fmt.Errorf("policy file must contain at most one quorum line")
			}
			q := fields[1]
			if q != "none" && !definedNames[q] {
				return nil, fmt.Errorf("quorum references undefined name %q", q)
			}
		case "log", "witness":
			return nil, fmt.Errorf("policy files must not contain %q lines", keyword)
		default:
			return nil, fmt.Errorf("unrecognised keyword %q in policy file", keyword)
		}
		lines = append(lines, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	if err := checkRoleGroupsPaired(roleGroups); err != nil {
		return nil, err
	}
	if quorumCount == 0 {
		return nil, fmt.Errorf("policy file must contain a quorum line")
	}

	return trimTrailingBlankLines(lines), nil
}

// resolveRoleGroupLine validates and tracks one "group-log" or "group-verifier"
// line. If the line matches role, emit is true and rewritten is the line with
// its keyword replaced by "group".
func resolveRoleGroupLine(line, trimmed string, fields []string, role string, roleGroups map[string]map[string]bool) (rewritten, name string, emit bool, err error) {
	keyword := fields[0]
	if len(fields) < 4 {
		return "", "", false, fmt.Errorf("invalid %s line: %q", keyword, trimmed)
	}
	name = fields[1]
	lineRole := strings.TrimPrefix(keyword, roleGroupPrefix)
	if roleGroups[name] == nil {
		roleGroups[name] = make(map[string]bool)
	}
	if roleGroups[name][lineRole] {
		return "", "", false, fmt.Errorf("more than one %s line for %q", keyword, name)
	}
	roleGroups[name][lineRole] = true
	if lineRole != role {
		return "", name, false, nil
	}
	// Rewrite the keyword, dropping any padding that aligned the pair of lines
	// with each other.
	i := strings.Index(line, keyword)
	rewritten = line[:i] + "group " + strings.TrimLeft(line[i+len(keyword):], " \t")
	return rewritten, name, true, nil
}

func checkRoleGroupsPaired(roleGroups map[string]map[string]bool) error {
	var unpaired []string
	for name, roles := range roleGroups {
		if !roles[roleLog] || !roles[roleVerifier] {
			unpaired = append(unpaired, name)
		}
	}
	if len(unpaired) > 0 {
		sort.Strings(unpaired)
		return fmt.Errorf("groups need both a %s and a %s line: %s",
			roleGroupPrefix+roleLog, roleGroupPrefix+roleVerifier, strings.Join(unpaired, ", "))
	}
	return nil
}

func trimTrailingBlankLines(lines []string) []string {
	for len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}
