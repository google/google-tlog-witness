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

package policycheck

import (
	"fmt"
	"math/bits"
	"sort"
	"strings"

	"github.com/transparency-dev/formats/policy"
)

// maxWitnessUniverse bounds the exhaustive search performed by Implies.
//
// Implies enumerates every subset of the combined witness set, so its cost
// is 2^n. Twenty witnesses is a little over a million subsets, which takes
// well under a second; beyond that the check would become a build-time
// hazard, so it fails loudly rather than silently taking a long time.
//
// Real policies are far smaller than this: the PAIC policies in this
// repository declare six witnesses.
const maxWitnessUniverse = 20

// UnsafeQuorumError reports a witness set that the log policy considers
// sufficient but the verifier policy does not.
//
// Its existence means the log is permitted to publish a checkpoint that a
// conforming verifier would reject.
type UnsafeQuorumError struct {
	// Witnesses are the verifier keys of the witnesses in the offending
	// set. It is a minimal such set: no proper subset of it satisfies the
	// log quorum.
	Witnesses []string
	// Labels holds a short human-readable description of each entry in
	// Witnesses, in the same order. Raw vkeys are unhelpful in a failure
	// message — an ML-DSA-44 one is some 2,500 characters long — so
	// Error() reports these instead.
	Labels []string
	// LogQuorum and VerifierQuorum are the quorum names of the two
	// policies, included to make failures self-describing.
	LogQuorum      string
	VerifierQuorum string
}

func (e *UnsafeQuorumError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "log quorum %q is weaker than verifier quorum %q: ",
		e.LogQuorum, e.VerifierQuorum)
	if len(e.Witnesses) == 0 {
		b.WriteString("the log may publish a checkpoint with no cosignatures at all, " +
			"which the verifier would reject")
		return b.String()
	}
	fmt.Fprintf(&b, "the log may publish a checkpoint cosigned only by [%s], "+
		"which the verifier would reject", strings.Join(e.Labels, ", "))
	return b.String()
}

// label describes a witness key as briefly as it can while staying
// unambiguous.
//
// It prefers the name the policy gives the witness, and falls back to the
// vkey's own name and key ID (a vkey is "<name>+<keyid>+<base64 key>", so
// trimming after the second '+' drops only the bulky key material).
func label(p *policy.TLogPolicy, vkey string) string {
	short := vkey
	if i := strings.Index(vkey, "+"); i >= 0 {
		if j := strings.Index(vkey[i+1:], "+"); j >= 0 {
			short = vkey[:i+1+j]
		}
	}
	for _, w := range p.Witnesses {
		if w.VKey == vkey {
			return fmt.Sprintf("%s (%s)", w.Name, short)
		}
	}
	return short
}

// Implies checks that every checkpoint the log policy permits would be
// accepted by the verifier policy.
//
// Formally, it verifies that for every set S of witnesses,
//
//	satisfies(log, S) implies satisfies(verifier, S)
//
// If that does not hold, the log is able to publish a checkpoint which a
// verifier applying the verifier policy would reject: an outage in which
// otherwise-valid entries cannot be verified. The returned error is an
// [*UnsafeQuorumError] naming a minimal witness set that demonstrates the
// problem.
//
// The check is exhaustive rather than heuristic. Quorum rules are monotone
// boolean functions over the witness set, so it is sound to enumerate
// subsets of the union of both policies' witnesses; every relevant
// distinction is captured by which of those keys are present.
//
// Note the direction: a verifier quorum that is *weaker* than the log quorum
// is fine, and is exactly the intermediate state the rollout procedure in
// README.md relies on. Only the reverse is unsafe.
//
// Implies deliberately ignores the two policies' log declarations. Whether a
// checkpoint is signed by a trusted log is orthogonal to the quorum
// relationship being checked here.
func Implies(log, verifier *policy.TLogPolicy) error {
	universe := union(vkeys(log), vkeys(verifier))
	if len(universe) > maxWitnessUniverse {
		return fmt.Errorf("cannot check %d witnesses exhaustively (limit %d): "+
			"the number of subsets to consider is 2^n",
			len(universe), maxWitnessUniverse)
	}

	// Enumerate every subset, keeping the smallest counterexample found.
	// Reporting a minimal set makes the failure far easier to act on than
	// an arbitrary one would be.
	best := -1
	var bestSet []string
	for mask := 0; mask < 1<<len(universe); mask++ {
		if best >= 0 && bits.OnesCount(uint(mask)) >= best {
			// Cannot improve on the counterexample already found.
			continue
		}
		have := make(witnessSet, len(universe))
		var present []string
		for i, k := range universe {
			if mask&(1<<i) != 0 {
				have[k] = true
				present = append(present, k)
			}
		}
		if satisfies(log, have) && !satisfies(verifier, have) {
			best = len(present)
			bestSet = present
		}
	}
	if best < 0 {
		return nil
	}
	labels := make([]string, len(bestSet))
	for i, k := range bestSet {
		// A key may be declared by only one of the two policies — indeed
		// that is itself a common cause of failure here — so fall back to
		// the verifier's naming if the log does not know the key.
		if l := label(log, k); strings.Contains(l, " (") {
			labels[i] = l
		} else {
			labels[i] = label(verifier, k)
		}
	}
	return &UnsafeQuorumError{
		Witnesses:      bestSet,
		Labels:         labels,
		LogQuorum:      log.Quorum,
		VerifierQuorum: verifier.Quorum,
	}
}

// union returns the sorted, deduplicated union of the given key slices.
// Sorting keeps subset enumeration, and therefore error messages, stable.
func union(a, b []string) []string {
	seen := make(map[string]bool, len(a)+len(b))
	for _, s := range a {
		seen[s] = true
	}
	for _, s := range b {
		seen[s] = true
	}
	out := make([]string, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
