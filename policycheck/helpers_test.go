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
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	f_note "github.com/transparency-dev/formats/note"
	"golang.org/x/mod/sumdb/note"
)

// testOrigin is the log origin used by every checkpoint built here. Per the
// tlog-policy spec a log's key name must match its origin line.
const testOrigin = "example.com/log/0"

// witnessKey is a generated witness identity: an Ed25519 key expressed as a
// cosignature/v1 verifier key, which is what tlog-policy requires of
// witnesses.
type witnessKey struct {
	name string
	skey string
	vkey string
}

// newWitness generates a witness identity for use in tests.
func newWitness(t *testing.T, name string) witnessKey {
	t.Helper()
	skey, vkey, err := note.GenerateKey(rand.Reader, name)
	if err != nil {
		t.Fatalf("GenerateKey(%q): %v", name, err)
	}
	cosigVKey, err := f_note.VKeyToCosignatureV1(vkey)
	if err != nil {
		t.Fatalf("VKeyToCosignatureV1(%q): %v", name, err)
	}
	return witnessKey{name: name, skey: skey, vkey: cosigVKey}
}

// signer returns a note.Signer producing cosignature/v1 signatures for w.
func (w witnessKey) signer(t *testing.T) note.Signer {
	t.Helper()
	s, err := f_note.NewSignerForCosignatureV1(w.skey)
	if err != nil {
		t.Fatalf("NewSignerForCosignatureV1(%q): %v", w.name, err)
	}
	return s
}

// logKey is a generated log identity. Logs sign checkpoints with an
// ordinary note signature rather than a cosignature.
type logKey struct {
	skey string
	vkey string
}

// newLog generates a log identity whose key name is testOrigin.
func newLog(t *testing.T) logKey {
	t.Helper()
	skey, vkey, err := note.GenerateKey(rand.Reader, testOrigin)
	if err != nil {
		t.Fatalf("GenerateKey(%q): %v", testOrigin, err)
	}
	return logKey{skey: skey, vkey: vkey}
}

// checkpoint builds a tlog-checkpoint note signed by l and cosigned by each
// of the given witnesses.
func checkpoint(t *testing.T, l logKey, size uint64, witnesses ...witnessKey) []byte {
	t.Helper()

	hash := sha256.Sum256([]byte(fmt.Sprintf("root at %d", size)))
	body := fmt.Sprintf("%s\n%d\n%s\n",
		testOrigin, size, base64.StdEncoding.EncodeToString(hash[:]))

	logSigner, err := note.NewSigner(l.skey)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	signers := []note.Signer{logSigner}
	for _, w := range witnesses {
		signers = append(signers, w.signer(t))
	}

	signed, err := note.Sign(&note.Note{Text: body}, signers...)
	if err != nil {
		t.Fatalf("note.Sign: %v", err)
	}
	return signed
}

// policyText assembles a tlog-policy document from its parts. Witness lines
// are emitted in the order given, so groups may refer to any witness.
func policyText(l logKey, witnesses []witnessKey, groups []string, quorum string) string {
	var b strings.Builder
	if l.vkey != "" {
		fmt.Fprintf(&b, "log %s\n", l.vkey)
	}
	for _, w := range witnesses {
		fmt.Fprintf(&b, "witness %s %s\n", w.name, w.vkey)
	}
	for _, g := range groups {
		fmt.Fprintf(&b, "%s\n", g)
	}
	fmt.Fprintf(&b, "quorum %s\n", quorum)
	return b.String()
}
