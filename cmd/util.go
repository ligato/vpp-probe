package cmd

import (
	"fmt"

	"github.com/gookit/color"
	"google.golang.org/protobuf/reflect/protoreflect"

	"go.ligato.io/vpp-probe/pkg/strutil"
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

func protoFieldsToMap(fields protoreflect.FieldDescriptors, pb protoreflect.Message) map[string]string {
	m := map[string]string{}
	for i := 0; i < fields.Len(); i++ {
		fd := fields.Get(i)
		if pb.Has(fd) {
			f := pb.Get(fd)
			if f.IsValid() {
				str := f.String()
				if fd.Enum() != nil {
					str = string(fd.Enum().Values().ByNumber(f.Enum()).Name())
				}
				m[fd.TextName()] = str
			}
		}
	}
	return m
}

func mapValuesColorized(m map[string]string, clr Colorer) string {
	return strutil.MapKeyValString(m, func(k string, v string) string {
		return fmt.Sprintf("%s:%s", k, colorize(clr, v))
	})
}
