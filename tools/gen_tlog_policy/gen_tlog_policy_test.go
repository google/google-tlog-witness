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
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

var binary = flag.String("binary", "", "Path to the gen_tlog_policy binary.")

const sampleLogList = `logs/v0
vkey example.com/log+deadbeef+AAAA
`

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

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func runGenPolicy(t *testing.T, role, logList, witness, policy string) (string, error) {
	t.Helper()
	if *binary == "" {
		t.Fatal("--binary must be set")
	}
	dir := t.TempDir()
	logPath := writeFile(t, dir, "logs.txt", logList)
	policyPath := writeFile(t, dir, "policy.txt", policy)
	args := []string{
		"--role=" + role,
		"--log-list=" + logPath,
		"--policy=" + policyPath,
	}
	if witness != "" {
		witnessPath := writeFile(t, dir, "witness.txt", witness)
		args = append(args, "--witnesses="+witnessPath)
	}
	cmd := exec.Command(runfile(t, *binary), args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func TestGenTlogPolicyRoleGroups(t *testing.T) {
	const witness = `# An operator rotating a key.
witness w-old vkey-old https://w.example
witness w-new vkey-new https://w.example
group-log      w all w-old w-new
group-verifier w any w-old w-new

group operator any w
`
	const policy = `# Product quorum.
group-log      q all operator
group-verifier q any operator
quorum q
`

	for _, tc := range []struct {
		role         string
		wantContains []string
		wantAbsent   []string
	}{
		{
			role: "log",
			wantContains: []string{
				"log example.com/log+deadbeef+AAAA",
				"witness w-old vkey-old https://w.example",
				"witness w-new vkey-new https://w.example",
				"\ngroup w all w-old w-new\n",
				"\ngroup operator any w\n",
				"\ngroup q all operator\n",
				"\nquorum q\n",
			},
			wantAbsent: []string{"group-log", "group-verifier", "group w any", "group q any"},
		},
		{
			role: "verifier",
			wantContains: []string{
				"log example.com/log+deadbeef+AAAA",
				"witness w-old vkey-old https://w.example",
				"witness w-new vkey-new https://w.example",
				"\ngroup w any w-old w-new\n",
				"\ngroup operator any w\n",
				"\ngroup q any operator\n",
				"\nquorum q\n",
			},
			wantAbsent: []string{"group-log", "group-verifier", "group w all", "group q all"},
		},
	} {
		t.Run(tc.role, func(t *testing.T) {
			out, err := runGenPolicy(t, tc.role, sampleLogList, witness, policy)
			if err != nil {
				t.Fatalf("gen_tlog_policy failed: %v\noutput:\n%s", err, out)
			}
			for _, want := range tc.wantContains {
				if !strings.Contains(out, want) {
					t.Errorf("output missing %q\nfull output:\n%s", want, out)
				}
			}
			for _, absent := range tc.wantAbsent {
				if strings.Contains(out, absent) {
					t.Errorf("output unexpectedly contains %q\nfull output:\n%s", absent, out)
				}
			}
		})
	}
}

func TestGenTlogPolicyQuorumNone(t *testing.T) {
	out, err := runGenPolicy(t, "log", sampleLogList, "", "quorum none\n")
	if err != nil {
		t.Fatalf("gen_tlog_policy failed: %v\noutput:\n%s", err, out)
	}
	if !strings.Contains(out, "\nquorum none\n") {
		t.Errorf("output missing quorum none:\n%s", out)
	}
}

func TestGenTlogPolicyErrors(t *testing.T) {
	const validWitness = "witness w1 vkey1 https://w1.example\nwitness w2 vkey2 https://w2.example\n"
	const validPolicy = "quorum w1\n"

	for _, tc := range []struct {
		name    string
		role    string
		witness string
		policy  string
		wantErr string
	}{
		{
			name:    "invalid role",
			role:    "other",
			witness: validWitness,
			policy:  validPolicy,
			wantErr: `--role must be "log" or "verifier"`,
		},
		{
			name:    "witness group-log without group-verifier",
			role:    "log",
			witness: validWitness + "group-log g all w1\n",
			policy:  validPolicy,
			wantErr: "groups need both a group-log and a group-verifier line: g",
		},
		{
			name:    "witness repeated group-log",
			role:    "log",
			witness: validWitness + "group-log g all w1\ngroup-log g any w1\ngroup-verifier g any w1\n",
			policy:  validPolicy,
			wantErr: `more than one group-log line for "g"`,
		},
		{
			name:    "witness quorum forbidden",
			role:    "log",
			witness: validWitness + "quorum w1\n",
			policy:  validPolicy,
			wantErr: `witness files must not contain "quorum" lines`,
		},
		{
			name:    "policy missing quorum",
			role:    "log",
			witness: validWitness,
			policy:  "group g any w1 w2\n",
			wantErr: "policy file must contain a quorum line",
		},
		{
			name:    "policy duplicate quorum",
			role:    "log",
			witness: validWitness,
			policy:  "quorum w1\nquorum w2\n",
			wantErr: "at most one quorum line",
		},
		{
			name:    "policy undefined quorum",
			role:    "log",
			witness: validWitness,
			policy:  "quorum nobody\n",
			wantErr: `quorum references undefined name "nobody"`,
		},
		{
			name:    "policy undefined group member",
			role:    "log",
			witness: validWitness,
			policy:  "group g any w1 nobody\nquorum g\n",
			wantErr: `group "g" references undefined name "nobody"`,
		},
		{
			name:    "policy duplicate name with witness",
			role:    "log",
			witness: validWitness,
			policy:  "group w1 any w2\nquorum w1\n",
			wantErr: `duplicate name "w1"`,
		},
		{
			name:    "policy unpaired group-log",
			role:    "verifier",
			witness: validWitness,
			policy:  "group-log g any w1\nquorum w1\n",
			wantErr: "groups need both a group-log and a group-verifier line: g",
		},
		{
			name:    "policy quorum references half-defined role group",
			role:    "log",
			witness: validWitness,
			policy:  "group-log g any w1\nquorum g\ngroup-verifier g any w1\n",
			wantErr: `quorum references undefined name "g"`,
		},
		{
			name:    "policy witness line forbidden",
			role:    "log",
			witness: validWitness,
			policy:  "witness w3 vkey3 https://w3.example\nquorum w1\n",
			wantErr: `policy files must not contain "witness" lines`,
		},
		{
			name:    "policy log line forbidden",
			role:    "log",
			witness: validWitness,
			policy:  "log vkey\nquorum w1\n",
			wantErr: `policy files must not contain "log" lines`,
		},
		{
			name:    "policy unknown keyword",
			role:    "log",
			witness: validWitness,
			policy:  "bogus foo\nquorum w1\n",
			wantErr: `unrecognised keyword "bogus"`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := runGenPolicy(t, tc.role, sampleLogList, tc.witness, tc.policy)
			if err == nil {
				t.Fatalf("expected error containing %q, but succeeded with output:\n%s", tc.wantErr, out)
			}
			if !strings.Contains(out, tc.wantErr) {
				t.Errorf("stderr/stdout:\n%s\nwant it to contain %q", out, tc.wantErr)
			}
		})
	}
}
