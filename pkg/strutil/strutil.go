package strutil

import (
	"io"
	"strings"

	"github.com/segmentio/textio"
)

const DefaultIndent = "  "

// IndentedWriter returns a writer that indents each line written to w with
// DefaultIndent.
func IndentedWriter(w io.Writer) *textio.PrefixWriter {
	return PrefixWriter(w, DefaultIndent)
}

// PrefixWriter returns a writer that adds prefix to each line written to w.
func PrefixWriter(w io.Writer, prefix string) *textio.PrefixWriter {
	return textio.NewPrefixWriter(w, prefix)
}

// MapKeyValString runs fn func for each key-value pair from map m and returns
// concatenated string.
func MapKeyValString(m map[string]string, fn func(k string, v string) string) string {
	ss := make([]string, 0, len(m))
	for k, v := range m {
		s := fn(k, v)
		if s == "" {
			continue
		}
		ss = append(ss, s)
	}
	return strings.Join(ss, " ")
}
