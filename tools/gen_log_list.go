// gen_log_list concatenates multiple per-product log-list files into a single
// combined log list following the witness-network log-list format:
// https://github.com/transparency-dev/witness-network/blob/main/log-list-format.md
//
// Each input file must contain a "logs/v0" header line. The output contains a
// single "logs/v0" header, followed by the log entries from each input file,
// separated by source-file header comments.
//
// Usage:
//
//	gen_log_list --input=<log-list-file> [--input=<log-list-file>...] [--output=<path>]
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/google/google-tlog-witness/internal/flagutil"
)

var (
	inputs = flagutil.StringSlice("input", "path to a log-list file (repeatable, required)")
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
	if len(*inputs) == 0 {
		return fmt.Errorf("at least one --input is required")
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

	seenVkeys := make(map[string]string) // vkey value -> source file path

	fmt.Fprintln(w, "logs/v0")

	for _, path := range *inputs {
		entries, err := extractLogEntries(path)
		if err != nil {
			return fmt.Errorf("%s: %v", path, err)
		}

		for _, e := range entries {
			if e.vkey != "" {
				if prev, ok := seenVkeys[e.vkey]; ok {
					return fmt.Errorf("duplicate vkey %q found in %s and %s", e.vkey, prev, path)
				}
				seenVkeys[e.vkey] = path
			}
		}

		fmt.Fprintf(w, "\n# From %s\n", path)
		for _, e := range entries {
			fmt.Fprintln(w, e.line)
		}
	}

	return nil
}

type logEntry struct {
	line string
	vkey string // non-empty only for "vkey ..." lines
}

// extractLogEntries reads a log-list file and returns all lines after the
// "logs/v0" header, skipping leading blank lines.
func extractLogEntries(path string) ([]logEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	pastHeader := false
	var entries []logEntry

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if !pastHeader {
			if trimmed == "logs/v0" {
				pastHeader = true
			}
			continue
		}

		// Skip leading blank lines after the header.
		if len(entries) == 0 && trimmed == "" {
			continue
		}

		var vkey string
		if strings.HasPrefix(trimmed, "vkey ") {
			vkey = strings.Fields(trimmed)[1]
		}

		entries = append(entries, logEntry{line: trimmed, vkey: vkey})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if !pastHeader {
		return nil, fmt.Errorf("missing 'logs/v0' header")
	}

	return entries, nil
}
