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

// gen_witness_list concatenates witness config files into a single witness
// list containing every witness and group they define, as seen by one role.
//
// The output is a witness config file, not a tlog-policy: it contains no "log"
// lines and no "quorum" line. Each input is preceded by a header comment
// identifying the source, followed by its contents with role-qualified group
// lines ("group-log" and "group-verifier") resolved for --role: the line for
// that role is emitted as a plain "group" line and the other is dropped. A
// name defined by more than one input is an error.
//
// Usage:
//
//	gen_witness_list --role=<log|verifier>
//	    --input=<witness-file> [--input=<witness-file>...] [--output=<path>]
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/google/google-tlog-witness/internal/flagutil"
	"github.com/google/google-tlog-witness/internal/section"
)

var (
	role   = flag.String("role", "", "role whose view of the witnesses to emit: \"log\" or \"verifier\" (required)")
	inputs = flagutil.StringSlice("input", "path to a witness config file (repeatable, required)")
	output = flag.String("output", "", "path to write the output file (defaults to stdout)")
)

func main() {
	flag.Parse()

	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	if *role != section.RoleLog && *role != section.RoleVerifier {
		return fmt.Errorf("--role must be %q or %q, got %q", section.RoleLog, section.RoleVerifier, *role)
	}
	if len(*inputs) == 0 {
		return fmt.Errorf("at least one --input is required")
	}

	// Resolve every input before writing anything, so that a failure leaves
	// no partial output.
	lines := []string{fmt.Sprintf("# Witness list for the %s role. This is not a tlog-policy.", *role)}
	definedNames := make(map[string]bool)
	for _, path := range *inputs {
		content, err := section.ResolveFile(path, *role, section.Witnesses, definedNames)
		if err != nil {
			return fmt.Errorf("processing witness file %s: %v", path, err)
		}
		lines = append(lines, "", fmt.Sprintf("# Witnesses from %s", path))
		lines = append(lines, content...)
	}

	w := os.Stdout
	if *output != "" {
		f, err := os.Create(*output)
		if err != nil {
			return fmt.Errorf("creating output file: %v", err)
		}
		defer f.Close()
		w = f
	}
	for _, line := range lines {
		if _, err := fmt.Fprintln(w, line); err != nil {
			return fmt.Errorf("writing output: %v", err)
		}
	}
	return nil
}
