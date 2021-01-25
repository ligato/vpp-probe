package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/docker/docker/pkg/term"
	"github.com/gookit/color"
	"google.golang.org/protobuf/reflect/protoreflect"
)

var coloredOutput bool

func init() {
	if term.IsTerminal(os.Stdout.Fd()) {
		coloredOutput = os.Getenv("NOCOLOR") == ""
	}
}

type Colorer interface {
	Code() string
}

func colorTag(x Colorer, s interface{}) string {
	if !coloredOutput || x == nil {
		return fmt.Sprint(s)
	}

	fg := ""
	op := ""

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

	tag := ""
	if fg != "" {
		tag = fmt.Sprintf("fg=%s", fg)
	}
	if op != "" {
		if tag != "" {
			tag += ";"
		}
		tag += fmt.Sprintf("op=%s", op)
	}

	return color.WrapTag(fmt.Sprint(s), tag)
}

func prefixString(s, prefix string) string {
	s = strings.TrimRight(s, "\n")
	lines := strings.Split(s, "\n")
	prefixed := strings.Join(lines, "\n"+prefix)
	return fmt.Sprintf(prefix+"%s\n", prefixed)
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
