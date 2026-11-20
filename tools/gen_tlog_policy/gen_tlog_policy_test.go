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
