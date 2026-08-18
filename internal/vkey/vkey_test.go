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

package vkey

import (
	"encoding/base64"
	"strings"
	"testing"
)

// synthVkey builds a vkey with the given algorithm byte and a fixed 32-byte
// key body. The key ID is not recomputed; nothing under test verifies it.
func synthVkey(origin string, alg byte) string {
	key := append([]byte{alg}, make([]byte, 32)...)
	return origin + "+deadbeef+" + base64.StdEncoding.EncodeToString(key)
}

func TestValidateWitnessKeyType(t *testing.T) {
	for _, tc := range []struct {
		name    string
		vkey    string
		wantErr bool
	}{
		{
			name: "ed25519 cosignature (0x04) accepted",
			vkey: synthVkey("witness.example.com", 0x04),
		},
		{
			name: "ml-dsa-44 (0x06) accepted",
			vkey: synthVkey("witness.example.com", 0x06),
		},
		{
			name:    "plain ed25519 (0x01) rejected",
			vkey:    synthVkey("witness.example.com", 0x01),
			wantErr: true,
		},
		{
			name:    "ecdsa (0x02) rejected",
			vkey:    synthVkey("witness.example.com", 0x02),
			wantErr: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			errs, _ := ValidateWitness(tc.vkey, 1)
			if got := len(errs) > 0; got != tc.wantErr {
				t.Errorf("ValidateWitness(%q) errors = %v, want error: %v", tc.vkey, errs, tc.wantErr)
			}
			if tc.wantErr && len(errs) > 0 && !strings.Contains(errs[0], "cosignature type") {
				t.Errorf("ValidateWitness(%q) error = %q, want it to mention the cosignature type", tc.vkey, errs[0])
			}
		})
	}
}

// Log keys legitimately use non-cosignature types (a log signs with a plain
// 0x01 Ed25519 key), so the structural validator must not reject them.
func TestValidateAcceptsNonCosignatureKeyTypes(t *testing.T) {
	for _, alg := range []byte{0x01, 0x02, 0x04, 0x06} {
		v := synthVkey("log.example.com", alg)
		if errs, _ := Validate(v, 1); len(errs) > 0 {
			t.Errorf("Validate(%q) with alg 0x%02x = %v, want no errors", v, alg, errs)
		}
	}
}

// A structurally invalid vkey should report the structural problem and not
// also emit a key type error.
func TestValidateWitnessStructuralErrorsOnly(t *testing.T) {
	errs, _ := ValidateWitness("no-separators-here", 1)
	if len(errs) != 1 {
		t.Fatalf("ValidateWitness() = %v, want exactly one structural error", errs)
	}
	if strings.Contains(errs[0], "cosignature type") {
		t.Errorf("ValidateWitness() = %q, want a structural error, not a key type error", errs[0])
	}
}
