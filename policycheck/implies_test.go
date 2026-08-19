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

package policycheck_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/google/google-tlog-witness/policycheck"
	"github.com/transparency-dev/formats/policy"
)

// parsePolicy parses policy text, failing the test if it is not valid.
func parsePolicy(t *testing.T, text string) *policy.TLogPolicy {
	t.Helper()
	var p policy.TLogPolicy
	if err := p.Unmarshal([]byte(text)); err != nil {
		t.Fatalf("Unmarshal(%q): %v", text, err)
	}
	return &p
}

func TestImplies(t *testing.T) {
	l := newLog(t)
	a := newWitness(t, "a.example.com")
	b := newWitness(t, "b.example.com")
	c := newWitness(t, "c.example.com")
	all := []witnessKey{a, b, c}

	for _, tc := range []struct {
		desc string
		// logGroups/logQuorum and verifierGroups/verifierQuorum describe the
		// two policies. Both declare the same three witnesses unless
		// logWitnesses/verifierWitnesses says otherwise.
		logWitnesses      []witnessKey
		logGroups         []string
		logQuorum         string
		verifierWitnesses []witnessKey
		verifierGroups    []string
		verifierQuorum    string
		// wantUnsafe is the number of witnesses in the expected minimal
		// counterexample, or -1 if the pair is expected to be safe.
		wantUnsafe int
	}{
		{
			desc:           "identical quorums are safe",
			logGroups:      []string{"group g all a.example.com b.example.com c.example.com"},
			logQuorum:      "g",
			verifierGroups: []string{"group g all a.example.com b.example.com c.example.com"},
			verifierQuorum: "g",
			wantUnsafe:     -1,
		},
		{
			desc: "weaker verifier is safe: this is the intermediate rollout state",
			// The log insists on all three; the verifier is content with one.
			logGroups:      []string{"group g all a.example.com b.example.com c.example.com"},
			logQuorum:      "g",
			verifierGroups: []string{"group g any a.example.com b.example.com c.example.com"},
			verifierQuorum: "g",
			wantUnsafe:     -1,
		},
		{
			desc: "stricter verifier is unsafe",
			// The log publishes with any one witness, but the verifier
			// demands all three, so a one-witness checkpoint is rejected.
			logGroups:      []string{"group g any a.example.com b.example.com c.example.com"},
			logQuorum:      "g",
			verifierGroups: []string{"group g all a.example.com b.example.com c.example.com"},
			verifierQuorum: "g",
			wantUnsafe:     1,
		},
		{
			desc:           "log requires nothing but verifier requires a witness",
			logGroups:      nil,
			logQuorum:      "none",
			verifierGroups: []string{"group g any a.example.com b.example.com c.example.com"},
			verifierQuorum: "g",
			// The empty set satisfies "none" but not "any".
			wantUnsafe: 0,
		},
		{
			desc:           "verifier requiring nothing is always safe",
			logGroups:      []string{"group g all a.example.com b.example.com c.example.com"},
			logQuorum:      "g",
			verifierQuorum: "none",
			wantUnsafe:     -1,
		},
		{
			desc:           "threshold mismatch is unsafe",
			logGroups:      []string{"group g 2 a.example.com b.example.com c.example.com"},
			logQuorum:      "g",
			verifierGroups: []string{"group g 3 a.example.com b.example.com c.example.com"},
			verifierQuorum: "g",
			wantUnsafe:     2,
		},
		{
			desc:           "threshold relaxation is safe",
			logGroups:      []string{"group g 3 a.example.com b.example.com c.example.com"},
			logQuorum:      "g",
			verifierGroups: []string{"group g 2 a.example.com b.example.com c.example.com"},
			verifierQuorum: "g",
			wantUnsafe:     -1,
		},
		{
			desc: "witness the verifier does not know is unsafe",
			// This is the shape of a botched key rotation: the log has been
			// updated to accept a new witness key before the verifier has.
			logWitnesses:      all,
			logGroups:         []string{"group g any a.example.com b.example.com c.example.com"},
			logQuorum:         "g",
			verifierWitnesses: []witnessKey{a, b},
			verifierGroups:    []string{"group g any a.example.com b.example.com"},
			verifierQuorum:    "g",
			// {c} alone satisfies the log but is invisible to the verifier.
			wantUnsafe: 1,
		},
		{
			desc: "nested groups are evaluated correctly",
			// Log: a, or both b and c. Verifier: a only.
			logWitnesses: all,
			logGroups: []string{
				"group bc all b.example.com c.example.com",
				"group g any a.example.com bc",
			},
			logQuorum:         "g",
			verifierWitnesses: all,
			verifierGroups:    []string{"group g all a.example.com"},
			verifierQuorum:    "g",
			// {b, c} satisfies the log but not the verifier.
			wantUnsafe: 2,
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			logWitnesses := tc.logWitnesses
			if logWitnesses == nil {
				logWitnesses = all
			}
			verifierWitnesses := tc.verifierWitnesses
			if verifierWitnesses == nil {
				verifierWitnesses = all
			}

			logPolicy := parsePolicy(t,
				policyText(l, logWitnesses, tc.logGroups, tc.logQuorum))
			verifierPolicy := parsePolicy(t,
				policyText(l, verifierWitnesses, tc.verifierGroups, tc.verifierQuorum))

			err := policycheck.Implies(logPolicy, verifierPolicy)

			if tc.wantUnsafe < 0 {
				if err != nil {
					t.Fatalf("Implies() = %v, want nil", err)
				}
				return
			}

			var unsafe *policycheck.UnsafeQuorumError
			if !errors.As(err, &unsafe) {
				t.Fatalf("Implies() = %v, want *UnsafeQuorumError", err)
			}
			if got := len(unsafe.Witnesses); got != tc.wantUnsafe {
				t.Errorf("counterexample has %d witnesses (%v), want %d",
					got, unsafe.Witnesses, tc.wantUnsafe)
			}
		})
	}
}

// TestImpliesCounterexampleIsMinimal checks that the reported witness set is
// as small as possible, since an unnecessarily large one would be harder to
// act on.
func TestImpliesCounterexampleIsMinimal(t *testing.T) {
	l := newLog(t)
	var witnesses []witnessKey
	var names []string
	for i := range 5 {
		w := newWitness(t, fmt.Sprintf("w%d.example.com", i))
		witnesses = append(witnesses, w)
		names = append(names, w.name)
	}
	joined := ""
	for _, n := range names {
		joined += " " + n
	}

	// The log publishes with any single witness; the verifier wants four.
	// The smallest demonstration of the gap is a single witness.
	logPolicy := parsePolicy(t, policyText(l, witnesses,
		[]string{"group g any" + joined}, "g"))
	verifierPolicy := parsePolicy(t, policyText(l, witnesses,
		[]string{"group g 4" + joined}, "g"))

	var unsafe *policycheck.UnsafeQuorumError
	if err := policycheck.Implies(logPolicy, verifierPolicy); !errors.As(err, &unsafe) {
		t.Fatalf("Implies() = %v, want *UnsafeQuorumError", err)
	}
	if len(unsafe.Witnesses) != 1 {
		t.Errorf("counterexample = %v, want a single witness", unsafe.Witnesses)
	}
}

// TestImpliesPAICProdShape exercises the quorum shape the PAIC policies
// actually use: an "all" over three operator groups, each of which is
// satisfied by any one of that operator's witnesses.
func TestImpliesPAICProdShape(t *testing.T) {
	l := newLog(t)
	tf1 := newWitness(t, "tf1.example.com")
	tf2 := newWitness(t, "tf2.example.com")
	geomys := newWitness(t, "geomys.example.com")
	g1 := newWitness(t, "g1.example.com")
	g2 := newWitness(t, "g2.example.com")
	witnesses := []witnessKey{tf1, tf2, geomys, g1, g2}

	groups := []string{
		"group tf all tf1.example.com tf2.example.com",
		"group geomys any geomys.example.com",
		"group glasklar any g1.example.com g2.example.com",
		"group tf-geomys-glasklar all tf geomys glasklar",
	}

	// A matched pair is safe.
	p := parsePolicy(t, policyText(l, witnesses, groups, "tf-geomys-glasklar"))
	if err := policycheck.Implies(p, p); err != nil {
		t.Errorf("Implies(prod, prod) = %v, want nil", err)
	}

	// Dropping geomys from the log side while the verifier still demands it
	// is the classic "verifier demands a cosignature the log cannot
	// produce" failure.
	logGroups := []string{
		"group tf all tf1.example.com tf2.example.com",
		"group glasklar any g1.example.com g2.example.com",
		"group tf-glasklar all tf glasklar",
	}
	logPolicy := parsePolicy(t, policyText(l, witnesses, logGroups, "tf-glasklar"))
	if err := policycheck.Implies(logPolicy, p); err == nil {
		t.Error("Implies(log without geomys, verifier with geomys) = nil, want error")
	}
}

// TestUnsafeQuorumErrorLabels checks that failures are reported with witness
// names rather than raw vkeys. This matters in practice: an ML-DSA-44 vkey is
// around 2,500 characters, so a message listing a few of them is unreadable.
func TestUnsafeQuorumErrorLabels(t *testing.T) {
	l := newLog(t)
	w1 := newWitness(t, "w1.example.com")
	w2 := newWitness(t, "w2.example.com")

	logPolicy := parsePolicy(t, policyText(l, []witnessKey{w1, w2},
		[]string{"group q any w1.example.com w2.example.com"}, "q"))
	verifier := parsePolicy(t, policyText(l, []witnessKey{w1, w2},
		[]string{"group q all w1.example.com w2.example.com"}, "q"))

	err := policycheck.Implies(logPolicy, verifier)
	var unsafe *policycheck.UnsafeQuorumError
	if !errors.As(err, &unsafe) {
		t.Fatalf("Implies() = %v, want *UnsafeQuorumError", err)
	}
	if got, want := len(unsafe.Labels), len(unsafe.Witnesses); got != want {
		t.Fatalf("len(Labels) = %d, want %d", got, want)
	}
	for i, got := range unsafe.Labels {
		if !strings.Contains(got, ".example.com (") {
			t.Errorf("Labels[%d] = %q, want a named witness", i, got)
		}
		if got == unsafe.Witnesses[i] {
			t.Errorf("Labels[%d] is the raw vkey, want a short label", i)
		}
	}
	if strings.Contains(unsafe.Error(), unsafe.Witnesses[0]) {
		t.Errorf("Error() embeds a raw vkey:\n%s", unsafe.Error())
	}
}
