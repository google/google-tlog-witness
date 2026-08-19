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

// Package policycheck provides safety checks over tlog-policy files.
//
// Two kinds of check are offered:
//
//   - [Implies] is a static comparison of two policies. It answers "can the
//     log produce a checkpoint that the verifier would reject?" without
//     reference to any real checkpoint.
//
//   - [CheckProof] evaluates a real tlog-proof against a policy. It answers
//     "would a verifier applying this policy accept this proof?"
//
// Together these guard the two halves of the tlog-policy rollout invariant
// described in the repository README: a verifier must never demand a
// cosignature the log cannot produce, and a policy change must never
// invalidate a proof that has already been issued.
package policycheck

import (
	"github.com/transparency-dev/formats/policy"
)

// quorumNone is the predefined quorum name meaning "no cosignatures
// required". It mirrors the same constant in the policy package, which does
// not export it.
const quorumNone = "none"

// witnessSet is a set of witness verifier keys. Verifier keys are used
// rather than witness names because names are policy-local: the same
// witness may be named differently in two policies, but its vkey is stable.
type witnessSet map[string]bool

// satisfies reports whether p's quorum rule is met when exactly the
// witnesses whose verifier keys are in have cosigned a checkpoint.
//
// This mirrors the evaluation performed by policy.TLogPolicy.Satisfied, but
// over an abstract set of verifier keys rather than the cosignatures on a
// concrete checkpoint. That makes it possible to reason about every witness
// set a policy could encounter, not just the ones we happen to have seen.
func satisfies(p *policy.TLogPolicy, have witnessSet) bool {
	if p.Quorum == quorumNone {
		return true
	}

	witnesses := make(map[string]policy.Witness, len(p.Witnesses))
	for _, w := range p.Witnesses {
		witnesses[w.Name] = w
	}
	groups := make(map[string]policy.Group, len(p.Groups))
	for _, g := range p.Groups {
		groups[g.Name] = g
	}

	visiting := make(map[string]bool)
	var sat func(string) bool
	sat = func(name string) bool {
		if w, ok := witnesses[name]; ok {
			return have[w.VKey]
		}
		g, ok := groups[name]
		// Unknown names and cyclic references (neither of which can occur in
		// a policy produced by Unmarshal) are never satisfied.
		if !ok || visiting[name] {
			return false
		}
		visiting[name] = true
		defer delete(visiting, name)
		count := uint(0)
		for _, m := range g.Members {
			if sat(m) {
				count++
				if count >= g.Threshold {
					return true
				}
			}
		}
		return g.Threshold == 0
	}
	return sat(p.Quorum)
}

// vkeys returns the verifier keys of every witness declared by p.
//
// Witnesses that are declared but unreachable from the quorum rule are
// included: they are part of the space of cosignatures the policy can
// recognise, even if they cannot contribute to satisfying it.
func vkeys(p *policy.TLogPolicy) []string {
	out := make([]string, 0, len(p.Witnesses))
	for _, w := range p.Witnesses {
		out = append(out, w.VKey)
	}
	return out
}
