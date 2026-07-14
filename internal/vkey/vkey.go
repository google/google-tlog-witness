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

// Package vkey provides validation for verification keys (vkeys) in the
// <origin>+<keyid>+<base64key> format used by tlog-policy and log-list files.
package vkey

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
)

// hexKeyIDRe matches a lowercase hex key ID (non-empty hex string).
var hexKeyIDRe = regexp.MustCompile(`^[0-9a-f]+$`)

// Validate checks that vkey has the form "<origin>+<keyid>+<base64key>",
// where <keyid> is a lowercase hex string and <base64key> is valid base64.
//
// The base64 key may itself contain '+', so we split on the *first* two '+'
// separators: everything before the first '+' is the origin, the token between
// the first and second '+' is the key ID, and everything after the second '+'
// (including any embedded '+' chars) is the base64 key.
//
// Returns a list of human-readable error strings (one per violation) and the
// extracted origin (empty on structural parse failure).
func Validate(vkey string, lineNum int) (errs []string, origin string) {
	first := strings.Index(vkey, "+")
	if first < 0 {
		return []string{fmt.Sprintf("line %d: vkey %q has no '+' separators; expected <origin>+<keyid>+<base64key>", lineNum, vkey)}, ""
	}
	second := strings.Index(vkey[first+1:], "+")
	if second < 0 {
		return []string{fmt.Sprintf("line %d: vkey %q has only one '+' separator; expected <origin>+<keyid>+<base64key>", lineNum, vkey)}, ""
	}
	second += first + 1 // adjust index to be relative to vkey

	origin = vkey[:first]
	keyID := vkey[first+1 : second]
	keyBase64 := vkey[second+1:]

	if origin == "" {
		errs = append(errs, fmt.Sprintf("line %d: vkey origin part is empty", lineNum))
	}
	if keyID == "" {
		errs = append(errs, fmt.Sprintf("line %d: vkey key ID part is empty", lineNum))
	} else if !hexKeyIDRe.MatchString(keyID) {
		errs = append(errs, fmt.Sprintf("line %d: vkey key ID %q is not lowercase hex", lineNum, keyID))
	}
	if keyBase64 == "" {
		errs = append(errs, fmt.Sprintf("line %d: vkey base64 key part is empty", lineNum))
	} else if _, err := base64.StdEncoding.DecodeString(keyBase64); err != nil {
		// Also try URL/raw variants before reporting an error.
		if _, err2 := base64.RawStdEncoding.DecodeString(keyBase64); err2 != nil {
			if _, err3 := base64.URLEncoding.DecodeString(keyBase64); err3 != nil {
				if _, err4 := base64.RawURLEncoding.DecodeString(keyBase64); err4 != nil {
					errs = append(errs, fmt.Sprintf("line %d: vkey base64 key %q is not valid base64: %v", lineNum, keyBase64, err))
				}
			}
		}
	}

	return errs, origin
}
