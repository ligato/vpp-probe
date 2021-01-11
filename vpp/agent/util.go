package agent

import (
	"fmt"
	"os"
	"strings"

	"github.com/docker/docker/pkg/term"
	"github.com/gookit/color"
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
