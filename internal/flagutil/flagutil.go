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

// Package flagutil provides helpers for defining repeated flag values.
package flagutil

import (
	"flag"
	"strings"
)

type stringSlice []string

func (s *stringSlice) String() string { return strings.Join(*s, ", ") }
func (s *stringSlice) Set(v string) error {
	*s = append(*s, v)
	return nil
}

// StringSlice registers a flag that can be specified multiple times to
// accumulate a slice of strings. It returns a pointer to the resulting
// slice, which is populated after flag.Parse is called.
//
// Example:
//
//	var inputs = flagutil.StringSlice("input", "path to an input file (repeatable)")
func StringSlice(name, usage string) *[]string {
	var s []string
	flag.Var((*stringSlice)(&s), name, usage)
	return &s
}
