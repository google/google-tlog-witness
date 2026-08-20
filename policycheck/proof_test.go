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
	"slices"
	"testing"

	"github.com/google/google-tlog-witness/policycheck"
	"github.com/transparency-dev/formats/proof"
)

// buildProof serialises a tlog-proof carrying the given checkpoint. The
// inclusion path is irrelevant to CheckProof, which evaluates only the
// policy-dependent parts of the proof.
func buildProof(cp []byte) []byte {
	return proof.TLogProof{Index: 0, Checkpoint: cp}.Marshal()
}

func TestCheckProof(t *testing.T) {
	l := newLog(t)
	a := newWitness(t, "a.example.com")
	b := newWitness(t, "b.example.com")
	c := newWitness(t, "c.example.com")
	all := []witnessKey{a, b, c}

	for _, tc := range []struct {
		desc string
		// cosigners are the witnesses that actually cosign the checkpoint.
		cosigners []witnessKey
		// groups/quorum define the verifier policy.
		groups []string
		quorum string
		wantOK bool
	}{
		{
			desc:      "quorum met exactly",
			cosigners: all,
			groups:    []string{"group g all a.example.com b.example.com c.example.com"},
			quorum:    "g",
			wantOK:    true,
		},
		{
			desc:      "quorum met with room to spare",
			cosigners: all,
			groups:    []string{"group g any a.example.com b.example.com c.example.com"},
			quorum:    "g",
			wantOK:    true,
		},
		{
			desc:      "quorum not met",
			cosigners: []witnessKey{a},
			groups:    []string{"group g all a.example.com b.example.com c.example.com"},
			quorum:    "g",
			wantOK:    false,
		},
		{
			desc: "quorum requiring a witness that did not cosign",
			// This is what a witness key rotation does to an older proof:
			// the key the policy now demands was not in use when the proof
			// was issued, so it can never appear.
			cosigners: []witnessKey{a, b},
			groups:    []string{"group g all c.example.com"},
			quorum:    "g",
			wantOK:    false,
		},
		{
			desc:      "no cosignatures required",
			cosigners: nil,
			quorum:    "none",
			wantOK:    true,
		},
		{
			desc:      "threshold met",
			cosigners: []witnessKey{a, b},
			groups:    []string{"group g 2 a.example.com b.example.com c.example.com"},
			quorum:    "g",
			wantOK:    true,
		},
		{
			desc:      "threshold not met",
			cosigners: []witnessKey{a},
			groups:    []string{"group g 2 a.example.com b.example.com c.example.com"},
			quorum:    "g",
			wantOK:    false,
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			cp := checkpoint(t, l, 100, tc.cosigners...)
			p := parsePolicy(t, policyText(l, all, tc.groups, tc.quorum))

			got := policycheck.CheckProof(p, buildProof(cp))

			if got.OK() != tc.wantOK {
				t.Fatalf("CheckProof().OK() = %v (err %v), want %v",
					got.OK(), got.Err, tc.wantOK)
			}
			if got.Origin != testOrigin {
				t.Errorf("Origin = %q, want %q", got.Origin, testOrigin)
			}

			// Whatever the verdict, the reported cosigners must be exactly
			// the witnesses that signed, so failures are diagnosable.
			var want []string
			for _, w := range tc.cosigners {
				want = append(want, w.vkey)
			}
			slices.Sort(want)
			if !slices.Equal(got.Cosigners, want) {
				t.Errorf("Cosigners = %v, want %v", got.Cosigners, want)
			}
		})
	}
}

// TestCheckProofUntrustedLog verifies that a checkpoint from a log the
// policy does not list is rejected even when the quorum is satisfied.
func TestCheckProofUntrustedLog(t *testing.T) {
	trusted := newLog(t)
	other := newLog(t)
	a := newWitness(t, "a.example.com")

	cp := checkpoint(t, other, 100, a)
	p := parsePolicy(t, policyText(trusted, []witnessKey{a},
		[]string{"group g any a.example.com"}, "g"))

	if got := policycheck.CheckProof(p, buildProof(cp)); got.OK() {
		t.Error("CheckProof() accepted a checkpoint from an untrusted log")
	}
}

// TestCheckProofEmpty checks that empty proof files are reported distinctly,
// so callers can skip them rather than treating them as policy failures.
func TestCheckProofEmpty(t *testing.T) {
	l := newLog(t)
	a := newWitness(t, "a.example.com")
	p := parsePolicy(t, policyText(l, []witnessKey{a},
		[]string{"group g any a.example.com"}, "g"))

	for _, raw := range [][]byte{nil, {}, []byte("   \n\n  ")} {
		got := policycheck.CheckProof(p, raw)
		if !errors.Is(got.Err, policycheck.ErrEmptyProof) {
			t.Errorf("CheckProof(%q).Err = %v, want ErrEmptyProof", raw, got.Err)
		}
	}
}

// TestCheckProofMalformed checks that garbage is rejected without panicking,
// and is not mistaken for an empty proof.
func TestCheckProofMalformed(t *testing.T) {
	l := newLog(t)
	a := newWitness(t, "a.example.com")
	p := parsePolicy(t, policyText(l, []witnessKey{a},
		[]string{"group g any a.example.com"}, "g"))

	for _, raw := range []string{
		"not a proof at all",
		"c2sp.org/tlog-proof@v1\n",
		"c2sp.org/tlog-proof@v1\nindex notanumber\n\ncheckpoint\n",
		"c2sp.org/tlog-proof@v1\nextra !!notbase64!!\nindex 0\n\ncheckpoint\n",
	} {
		got := policycheck.CheckProof(p, []byte(raw))
		if got.OK() {
			t.Errorf("CheckProof(%q) unexpectedly succeeded", raw)
		}
		if errors.Is(got.Err, policycheck.ErrEmptyProof) {
			t.Errorf("CheckProof(%q) reported ErrEmptyProof for non-empty input", raw)
		}
	}
}
