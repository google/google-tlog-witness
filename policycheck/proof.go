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
	"bytes"
	"errors"
	"fmt"
	"sort"

	"github.com/transparency-dev/formats/policy"
	"github.com/transparency-dev/formats/proof"
	"golang.org/x/mod/sumdb/note"
)

// ErrEmptyProof indicates that the input contained no data.
//
// Empty proof files are produced deliberately: a logger may be configured
// not to publish to a transparency log at all, or to tolerate a publishing
// failure rather than fail the release. Either way the absence of a proof
// was a decision made by whoever produced the artefact, and is not something
// a policy check can or should adjudicate. Callers are expected to skip
// these rather than treat them as failures.
var ErrEmptyProof = errors.New("proof is empty")

// Result describes the outcome of evaluating one tlog-proof against one
// policy.
type Result struct {
	// Origin is the checkpoint's origin line, identifying the log that
	// issued it. It is populated whenever the proof could be parsed, even
	// if verification subsequently failed, so that callers can route a
	// proof to the right policy.
	Origin string
	// Cosigners lists the verifier keys of the policy's witnesses whose
	// cosignatures are present and valid on the checkpoint, sorted.
	//
	// This is the raw material for diagnosing a quorum failure: it says
	// what the checkpoint actually carries, as opposed to what the policy
	// demanded.
	Cosigners []string
	// Err is nil if the policy accepts the proof.
	Err error
}

// OK reports whether the policy accepted the proof.
func (r Result) OK() bool { return r.Err == nil }

// CheckProof evaluates a serialised tlog-proof against a policy.
//
// It answers exactly the question a relying party asks: would a verifier
// applying this policy accept this proof? That means the checkpoint must be
// signed by one of the policy's logs and cosigned in accordance with its
// quorum rule.
//
// Merkle inclusion is deliberately not checked. Inclusion relates the proof
// to a specific logged entry, which requires that entry as an input and
// which no change to a policy can invalidate. Keeping it out lets a policy
// be checked against a corpus of proofs alone.
//
// If the input is empty, CheckProof returns a Result whose Err wraps
// [ErrEmptyProof].
func CheckProof(p *policy.TLogPolicy, raw []byte) Result {
	if len(bytes.TrimSpace(raw)) == 0 {
		return Result{Err: ErrEmptyProof}
	}

	var pr proof.TLogProof
	if err := pr.Unmarshal(raw); err != nil {
		return Result{Err: fmt.Errorf("parsing tlog-proof: %w", err)}
	}

	r := Result{
		Origin:    checkpointOrigin(pr.Checkpoint),
		Cosigners: cosigners(p, pr.Checkpoint),
	}
	if _, err := p.Verify(pr.Checkpoint); err != nil {
		r.Err = err
	}
	return r
}

// checkpointOrigin returns the origin line of a signed checkpoint note,
// which is its first line.
//
// The origin is read without verifying any signature. That is safe for the
// only use it is put to here — deciding which policy a proof should be
// evaluated against — because an incorrect origin can only cause the proof
// to be checked against the wrong policy, which then rejects it.
func checkpointOrigin(checkpoint []byte) string {
	line, _, _ := bytes.Cut(checkpoint, []byte("\n"))
	return string(line)
}

// cosigners returns the verifier keys of p's witnesses that have validly
// cosigned the checkpoint, sorted.
//
// Witnesses unknown to p are invisible here: a cosignature can only be
// attributed to a key the policy declares. That is the same view of the
// checkpoint the quorum rule takes.
func cosigners(p *policy.TLogPolicy, checkpoint []byte) []string {
	var out []string
	for _, w := range p.Witnesses {
		n, err := note.Open(checkpoint, note.VerifierList(w.Verifier))
		if err == nil && len(n.Sigs) == 1 {
			out = append(out, w.VKey)
		}
	}
	sort.Strings(out)
	return out
}
