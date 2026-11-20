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

package main

import (
	"slices"
	"strings"
	"testing"
)

func TestResolveWitnessFile(t *testing.T) {
	const input = `# An operator adding a second key.
witness w-old vkey-old https://w.example
witness w-new vkey-new https://w.example
group-log      w all w-old w-new
group-verifier w any w-old

group operator any w
`
	for _, tc := range []struct {
		role      string
		wantLines []string
		wantNames []string
	}{
		{
			role: roleLog,
			wantLines: []string{
				"# An operator adding a second key.",
				"witness w-old vkey-old https://w.example",
				"witness w-new vkey-new https://w.example",
				"group w all w-old w-new",
				"",
				"group operator any w",
			},
			wantNames: []string{"w-old", "w-new", "w", "operator"},
		},
		{
			role: roleVerifier,
			wantLines: []string{
				"# An operator adding a second key.",
				"witness w-old vkey-old https://w.example",
				"witness w-new vkey-new https://w.example",
				"group w any w-old",
				"",
				"group operator any w",
			},
			wantNames: []string{"w-old", "w-new", "w", "operator"},
		},
	} {
		t.Run(tc.role, func(t *testing.T) {
			lines, names, err := resolveWitnessFile(strings.NewReader(input), tc.role)
			if err != nil {
				t.Fatalf("resolveWitnessFile() error: %v", err)
			}
			if !slices.Equal(lines, tc.wantLines) {
				t.Errorf("lines:\n%s\nwant:\n%s", strings.Join(lines, "\n"), strings.Join(tc.wantLines, "\n"))
			}
			if !slices.Equal(names, tc.wantNames) {
				t.Errorf("names: %q, want %q", names, tc.wantNames)
			}
		})
	}
}

func TestResolveWitnessFileErrors(t *testing.T) {
	const witness = "witness w vkey https://w.example\n"
	for _, tc := range []struct {
		name    string
		input   string
		wantErr string
	}{
		{
			name:    "group-log without group-verifier",
			input:   witness + "group-log g all w\n",
			wantErr: "groups need both a group-log and a group-verifier line: g",
		},
		{
			name:    "group-verifier without group-log",
			input:   witness + "group-verifier g all w\n",
			wantErr: "groups need both a group-log and a group-verifier line: g",
		},
		{
			name:    "repeated group-log",
			input:   witness + "group-log g all w\ngroup-log g any w\ngroup-verifier g any w\n",
			wantErr: `more than one group-log line for "g"`,
		},
		{
			name:    "group-log without members",
			input:   witness + "group-log g all\ngroup-verifier g all w\n",
			wantErr: "invalid group-log line",
		},
		{
			name:    "quorum line",
			input:   witness + "quorum w\n",
			wantErr: `must not contain "quorum" lines`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, role := range []string{roleLog, roleVerifier} {
				_, _, err := resolveWitnessFile(strings.NewReader(tc.input), role)
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("resolveWitnessFile(role=%s) error: %v, want one containing %q", role, err, tc.wantErr)
				}
			}
		})
	}
}

func TestResolvePolicyFile(t *testing.T) {
	const input = `# Quorum rollout: add vendor3 on the log side first.
group-log      quorum-grp 2 vendor1 vendor2 vendor3
group-verifier quorum-grp 2 vendor1 vendor2
quorum quorum-grp
`
	witnessNames := map[string]bool{
		"vendor1": true,
		"vendor2": true,
		"vendor3": true,
	}

	for _, tc := range []struct {
		role      string
		wantLines []string
	}{
		{
			role: roleLog,
			wantLines: []string{
				"# Quorum rollout: add vendor3 on the log side first.",
				"group quorum-grp 2 vendor1 vendor2 vendor3",
				"quorum quorum-grp",
			},
		},
		{
			role: roleVerifier,
			wantLines: []string{
				"# Quorum rollout: add vendor3 on the log side first.",
				"group quorum-grp 2 vendor1 vendor2",
				"quorum quorum-grp",
			},
		},
	} {
		t.Run(tc.role, func(t *testing.T) {
			lines, err := resolvePolicyFile(strings.NewReader(input), tc.role, witnessNames)
			if err != nil {
				t.Fatalf("resolvePolicyFile() error: %v", err)
			}
			if !slices.Equal(lines, tc.wantLines) {
				t.Errorf("lines:\n%s\nwant:\n%s", strings.Join(lines, "\n"), strings.Join(tc.wantLines, "\n"))
			}
		})
	}
}

func TestResolvePolicyFileQuorumNone(t *testing.T) {
	lines, err := resolvePolicyFile(strings.NewReader("quorum none\n"), roleLog, map[string]bool{})
	if err != nil {
		t.Fatalf("resolvePolicyFile() error: %v", err)
	}
	if !slices.Equal(lines, []string{"quorum none"}) {
		t.Errorf("lines: %q, want [quorum none]", lines)
	}
}

func TestResolvePolicyFileErrors(t *testing.T) {
	witnessNames := map[string]bool{"v1": true, "v2": true}
	for _, tc := range []struct {
		name    string
		input   string
		wantErr string
	}{
		{
			name:    "missing quorum",
			input:   "group g any v1 v2\n",
			wantErr: "policy file must contain a quorum line",
		},
		{
			name:    "duplicate quorum",
			input:   "quorum v1\nquorum v2\n",
			wantErr: "at most one quorum line",
		},
		{
			name:    "undefined quorum",
			input:   "quorum nobody\n",
			wantErr: `quorum references undefined name "nobody"`,
		},
		{
			name:    "undefined group member",
			input:   "group g any v1 nobody\nquorum g\n",
			wantErr: `group "g" references undefined name "nobody"`,
		},
		{
			name:    "duplicate name with witness",
			input:   "group v1 any v2\nquorum v1\n",
			wantErr: `duplicate name "v1"`,
		},
		{
			name:    "unpaired group-log",
			input:   "group-log g any v1\nquorum v1\n",
			wantErr: "groups need both a group-log and a group-verifier line: g",
		},
		{
			name:    "quorum references half-defined role group",
			input:   "group-log g any v1\nquorum g\ngroup-verifier g any v1\n",
			wantErr: `quorum references undefined name "g"`,
		},
		{
			name:    "witness line forbidden",
			input:   "witness w vkey https://w.example\nquorum v1\n",
			wantErr: `must not contain "witness" lines`,
		},
		{
			name:    "log line forbidden",
			input:   "log vkey\nquorum v1\n",
			wantErr: `must not contain "log" lines`,
		},
		{
			name:    "unknown keyword",
			input:   "bogus foo\nquorum v1\n",
			wantErr: `unrecognised keyword "bogus"`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, role := range []string{roleLog, roleVerifier} {
				_, err := resolvePolicyFile(strings.NewReader(tc.input), role, witnessNames)
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("resolvePolicyFile(role=%s) error: %v, want one containing %q", role, err, tc.wantErr)
				}
			}
		})
	}
}
