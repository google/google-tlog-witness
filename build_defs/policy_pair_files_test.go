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

// Package policy_pair_files_test checks that a log policy can never produce a
// checkpoint that its paired verifier policy would reject.
//
// A tlog_policy_pair emits <name>-log.policy and <name>-verifier.policy from
// shared inputs. The log policy governs how many cosignatures the log gathers
// before it is willing to emit a tlog-proof; the verifier policy governs what
// a relying party will accept. If the verifier policy is stricter than the log
// policy, the log is free to emit tlog-proofs that no relying party can ever
// verify, which is an outage.
//
// This test enumerates every possible set of cosigning witnesses and fails if
// any of them satisfies the log policy but not the verifier policy.
package policy_pair_files_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/google-tlog-witness/policycheck"
)

// TestPolicyPairs checks each <name>-log.policy against its matching
// <name>-verifier.policy.
func TestPolicyPairs(t *testing.T) {
	matches, err := filepath.Glob("*-log.policy")
	if err != nil {
		t.Fatalf("globbing for *-log.policy: %v", err)
	}
	if len(matches) == 0 {
		t.Fatal("no *-log.policy files found — check the test data / working directory")
	}

	for _, logPath := range matches {
		name := strings.TrimSuffix(logPath, "-log.policy")
		verifierPath := name + "-verifier.policy"
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := os.Stat(verifierPath); err != nil {
				t.Fatalf("no verifier policy alongside %s: %v", logPath, err)
			}
			if err := policycheck.ImpliesFiles(logPath, verifierPath); err != nil {
				t.Errorf("%s does not imply %s: %v", logPath, verifierPath, err)
			}
		})
	}
}
