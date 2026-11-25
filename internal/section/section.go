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

// Package section reads witness and policy files and resolves their
// role-qualified groups ("group-log" and "group-verifier") for one role.
package section

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

// The roles a file can be resolved for.
const (
	RoleLog      = "log"
	RoleVerifier = "verifier"
)

// roleGroupPrefix starts the keyword of a role-qualified group line: it is
// followed by the role the line applies to.
const roleGroupPrefix = "group-"

// Kind identifies the type of an input file and the lines it may contain.
type Kind int

const (
	// Witnesses is a witness config file defining witnesses and groups.
	Witnesses Kind = iota
	// Policy is a policy file defining groups and a quorum rule.
	Policy
)

// String returns the name of k used in error messages.
func (k Kind) String() string {
	if k == Policy {
		return "policy"
	}
	return "witness"
}

// ResolveFile opens path and resolves it with Resolve.
func ResolveFile(path, role string, kind Kind, definedNames map[string]bool) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Resolve(f, role, kind, definedNames)
}

// Resolve reads a witness or policy file and returns its lines as they apply
// to role (preserving comments), recording newly defined witness and group
// names in definedNames.
//
// A group can be defined differently for the log and for verifiers by a pair
// of "group-log" and "group-verifier" lines sharing a name. The line for role
// is returned as a plain "group" line, and the other is left out. Each such
// name needs exactly one line for each role, and is added to definedNames once
// both have appeared.
func Resolve(r io.Reader, role string, kind Kind, definedNames map[string]bool) ([]string, error) {
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
			if kind != Witnesses {
				return nil, fmt.Errorf("%s files must not contain %q lines", kind, keyword)
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
		case roleGroupPrefix + RoleLog, roleGroupPrefix + RoleVerifier:
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
			if roleGroups[name][RoleLog] && roleGroups[name][RoleVerifier] {
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
			if kind != Policy {
				return nil, fmt.Errorf("%s files must not contain %q lines", kind, keyword)
			}
			if len(fields) != 2 {
				return nil, fmt.Errorf("invalid quorum line: %q", trimmed)
			}
			quorumCount++
			if quorumCount > 1 {
				return nil, fmt.Errorf("%s file must contain at most one quorum line", kind)
			}
			q := fields[1]
			if q != "none" && !definedNames[q] {
				return nil, fmt.Errorf("quorum references undefined name %q", q)
			}
		case "log":
			return nil, fmt.Errorf("%s files must not contain %q lines", kind, keyword)
		default:
			return nil, fmt.Errorf("unrecognised keyword %q in %s file", keyword, kind)
		}
		lines = append(lines, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	var unpaired []string
	for name, roles := range roleGroups {
		if !roles[RoleLog] || !roles[RoleVerifier] {
			unpaired = append(unpaired, name)
		}
	}
	if len(unpaired) > 0 {
		sort.Strings(unpaired)
		return nil, fmt.Errorf("groups need both a %s and a %s line: %s",
			roleGroupPrefix+RoleLog, roleGroupPrefix+RoleVerifier, strings.Join(unpaired, ", "))
	}
	if kind == Policy && quorumCount == 0 {
		return nil, fmt.Errorf("%s file must contain a quorum line", kind)
	}

	for len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) == "" {
		lines = lines[:len(lines)-1]
	}

	return lines, nil
}
