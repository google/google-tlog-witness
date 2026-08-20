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

// Package policy_pair_test checks that a log policy can never produce a
// checkpoint that its paired verifier policy would reject.
//
// The log policy governs how many cosignatures the log gathers before it is
// willing to emit a tlog-proof; the verifier policy governs what a relying
// party will accept. If the verifier policy is stricter than the log policy,
// the log is free to emit tlog-proofs that no relying party can ever verify,
// which is an outage.
//
// The two policies are named explicitly by flag. Checking one pair per test
// target keeps the mapping between them a property of the BUILD file rather
// than of a file-naming convention; a caller wanting several pairs checked
// instantiates the macro several times.
package policy_pair_test

import (
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/google-tlog-witness/policycheck"
)

var (
	logPolicy = flag.String("log_policy", "",
		"Path to the log tlog-policy file.")
	verifierPolicy = flag.String("verifier_policy", "",
		"Path to the verifier tlog-policy file.")
)

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

// TestLogPolicyImpliesVerifierPolicy asserts that every set of cosigning
// witnesses satisfying the log policy also satisfies the verifier policy.
func TestLogPolicyImpliesVerifierPolicy(t *testing.T) {
	if *logPolicy == "" || *verifierPolicy == "" {
		t.Fatal("both --log_policy and --verifier_policy must be set")
	}
	err := policycheck.ImpliesFiles(
		runfile(t, *logPolicy), runfile(t, *verifierPolicy))
	if err != nil {
		t.Errorf("%s does not imply %s: %v", *logPolicy, *verifierPolicy, err)
	}
}
