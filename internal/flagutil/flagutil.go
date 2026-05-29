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
