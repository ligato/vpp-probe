package cmd

import (
	"fmt"
	"io"
	"strings"

	"github.com/gookit/color"
	"github.com/segmentio/textio"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// nocolor is override for controling color in test
var nocolor bool

type Colorer interface {
	Code() string
}

func colorize(x Colorer, v interface{}) string {
	if nocolor || x == nil {
		return fmt.Sprint(v)
	}

	var (
		fg string
		op string
	)

	check := func(c Colorer) {
		for name, clr := range color.FgColors {
			if clr == c {
				fg = name
				break
			}
		}
		for name, clr := range color.ExFgColors {
			if clr == c {
				fg = name
				break
			}
		}
		for name, opt := range color.Options {
			if opt == c {
				op = name
				break
			}
		}
	}

	switch cc := x.(type) {
	case color.Style:
		for _, c := range cc {
			check(c)
		}
	default:
		check(x)
	}

	var tag string

	if fg != "" {
		tag = fmt.Sprintf("fg=%s", fg)
	}
	if op != "" {
		if tag != "" {
			tag += ";"
		}
		tag += fmt.Sprintf("op=%s", op)
	}

	return color.WrapTag(fmt.Sprint(v), tag)
}

func prefixWriter(w io.Writer) *textio.PrefixWriter {
	return textio.NewPrefixWriter(w, defaultPrefix)
}

func mapKeyValString(m map[string]string, f func(k string, v string) string) string {
	ss := make([]string, 0, len(m))
	for k, v := range m {
		s := f(k, v)
		if s == "" {
			continue
		}
		ss = append(ss, s)
	}
	return strings.Join(ss, " ")
}

func protoFieldsToMap(fields protoreflect.FieldDescriptors, pb protoreflect.Message) map[string]string {
	m := map[string]string{}
	for i := 0; i < fields.Len(); i++ {
		fd := fields.Get(i)
		if pb.Has(fd) {
			f := pb.Get(fd)
			if f.IsValid() {
				m[string(fd.Name())] = f.String()
			}
		}
	}
	return m
}
