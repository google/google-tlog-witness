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

package main_test

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

var binary = flag.String("binary", "", "Path to the gen_witness_list binary.")

// runfile resolves a workspace-relative path, as produced by Bazel's
// $(rootpath), to something executable.
func runfile(t *testing.T, path string) string {
	t.Helper()
	candidates := []string{path}
	if root := os.Getenv("TEST_SRCDIR"); root != "" {
		candidates = append(candidates,
			filepath.Join(root, os.Getenv("TEST_WORKSPACE"), path),
			filepath.Join(root, path))
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	t.Fatalf("cannot find %q; tried %v", path, candidates)
	return ""
}

// runGenWitnessList runs gen_witness_list for role over temporary witness
// config files with the given contents and returns its combined output.
func runGenWitnessList(t *testing.T, role string, witnessFiles ...string) (string, error) {
	t.Helper()
	if *binary == "" {
		t.Fatal("--binary must be set")
	}
	dir := t.TempDir()
	args := []string{"--role=" + role}
	for i, content := range witnessFiles {
		p := filepath.Join(dir, fmt.Sprintf("witness%d.txt", i))
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		args = append(args, "--input="+p)
	}
	out, err := exec.Command(runfile(t, *binary), args...).CombinedOutput()
	return string(out), err
}

const (
	rotatingWitness = `# An operator rotating a key.
witness w-old vkey-old https://w.example
witness w-new vkey-new https://w.example
group-log      w all w-old w-new
group-verifier w any w-old w-new
`
	plainWitness = `witness x1 vkey-x1 https://x.example
group x any x1
`
)

func TestGenWitnessList(t *testing.T) {
	for _, tc := range []struct {
		role         string
		wantContains []string
		wantAbsent   []string
	}{
		{
			role: "log",
			wantContains: []string{
				"# An operator rotating a key.\n",
				"\nwitness w-old vkey-old https://w.example\n",
				"\nwitness w-new vkey-new https://w.example\n",
				"\ngroup w all w-old w-new\n",
				"\nwitness x1 vkey-x1 https://x.example\n",
				"\ngroup x any x1\n",
			},
			wantAbsent: []string{"group-log", "group-verifier", "group w any", "\nquorum", "\nlog "},
		},
		{
			role: "verifier",
			wantContains: []string{
				"\nwitness w-old vkey-old https://w.example\n",
				"\nwitness w-new vkey-new https://w.example\n",
				"\ngroup w any w-old w-new\n",
				"\nwitness x1 vkey-x1 https://x.example\n",
				"\ngroup x any x1\n",
			},
			wantAbsent: []string{"group-log", "group-verifier", "group w all", "\nquorum", "\nlog "},
		},
	} {
		t.Run(tc.role, func(t *testing.T) {
			out, err := runGenWitnessList(t, tc.role, rotatingWitness, plainWitness)
			if err != nil {
				t.Fatalf("gen_witness_list --role=%s failed: %v\noutput:\n%s", tc.role, err, out)
			}
			for _, want := range tc.wantContains {
				if !strings.Contains(out, want) {
					t.Errorf("gen_witness_list --role=%s output is missing %q\nfull output:\n%s", tc.role, want, out)
				}
			}
			for _, absent := range tc.wantAbsent {
				if strings.Contains(out, absent) {
					t.Errorf("gen_witness_list --role=%s output unexpectedly contains %q\nfull output:\n%s", tc.role, absent, out)
				}
			}
		})
	}
}

func TestGenWitnessListErrors(t *testing.T) {
	for _, tc := range []struct {
		name         string
		role         string
		witnessFiles []string
		wantErr      string
	}{
		{
			name:         "invalid_role",
			role:         "other",
			witnessFiles: []string{plainWitness},
			wantErr:      `--role must be "log" or "verifier"`,
		},
		{
			name:    "no_inputs",
			role:    "log",
			wantErr: "at least one --input is required",
		},
		{
			name:         "name_defined_by_two_files",
			role:         "log",
			witnessFiles: []string{plainWitness, "witness x vkey-other https://other.example\n"},
			wantErr:      `duplicate name "x"`,
		},
		{
			name:         "quorum_line",
			role:         "log",
			witnessFiles: []string{plainWitness + "quorum x\n"},
			wantErr:      `witness files must not contain "quorum" lines`,
		},
		{
			name:         "log_line",
			role:         "log",
			witnessFiles: []string{plainWitness + "log vkey\n"},
			wantErr:      `witness files must not contain "log" lines`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := runGenWitnessList(t, tc.role, tc.witnessFiles...)
			if err == nil {
				t.Fatalf("gen_witness_list --role=%s succeeded, want an error containing %q\noutput:\n%s", tc.role, tc.wantErr, out)
			}
			if !strings.Contains(out, tc.wantErr) {
				t.Errorf("gen_witness_list --role=%s output:\n%s\nwant it to contain %q", tc.role, out, tc.wantErr)
			}
		})
	}
}
