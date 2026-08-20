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

// Package tlog_proof_test checks a corpus of already-issued tlog-proofs
// against a tlog-policy.
//
// This is the empirical counterpart to the policy_pair check. That one is
// static and forward-looking: it asks whether the log could ever produce
// something the verifier would reject. This one asks the question that
// matters when a policy is about to change: would the new policy invalidate
// proofs that have already been issued and shipped?
//
// A relying party that keeps its proofs under version control can point this
// test at them, so that tightening a policy fails the build rather than
// breaking verification in the field.
//
// The policy and the proofs are all named by flag. Proofs deliberately do not
// arrive as positional arguments: a test runner is free to append its own
// flags after ours, and those would otherwise be mistaken for filenames.
package tlog_proof_test

import (
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/google-tlog-witness/policycheck"
)

// stringSlice collects one flag given several times.
//
// This duplicates internal/flagutil rather than importing it: this file is
// compiled into the consuming package, which is generally outside this
// module and so cannot reach an internal package.
type stringSlice []string

func (s *stringSlice) String() string { return strings.Join(*s, ", ") }
func (s *stringSlice) Set(v string) error {
	*s = append(*s, v)
	return nil
}

var (
	policyPath = flag.String("policy", "",
		"Path to the tlog-policy file to check the proofs against.")
	proofPaths stringSlice
)

func init() {
	flag.Var(&proofPaths, "proof",
		"Path to a tlog-proof file to check. May be repeated.")
}

// runfile resolves a workspace-relative path, as produced by Bazel's
// $(rootpath), to something openable.
//
// Test runners differ in the working directory they use — some the root of
// the runfiles tree, some the directory of the package under test — so try
// the path as given before resolving it against the runfiles root.
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

// TestProofs checks every proof named by --proof against the policy.
func TestProofs(t *testing.T) {
	if *policyPath == "" {
		t.Fatal("--policy must be set")
	}
	if len(proofPaths) == 0 {
		t.Fatal("no tlog-proofs given; pass each one with --proof")
	}

	paths := make([]string, len(proofPaths))
	for i, p := range proofPaths {
		paths[i] = runfile(t, p)
	}
	results, err := policycheck.CheckProofFiles(runfile(t, *policyPath), paths)
	if err != nil {
		t.Fatalf("loading policy %s: %v", *policyPath, err)
	}

	var skipped int
	for i, r := range results {
		t.Run(proofPaths[i], func(t *testing.T) {
			if errors.Is(r.Err, policycheck.ErrEmptyProof) {
				// An empty proof means whoever produced the artefact chose
				// not to log it, or chose to tolerate a logging failure.
				// That is not something a policy check can adjudicate.
				skipped++
				t.Skip("proof is empty")
			}
			if r.Err != nil {
				t.Errorf("policy %s rejects this proof: %v\n"+
					"origin: %s\ncosigners accepted by the policy: %v",
					*policyPath, r.Err, r.Origin, r.Cosigners)
			}
		})
	}
	t.Logf("checked %d tlog-proofs (%d empty and skipped)", len(results), skipped)
}
