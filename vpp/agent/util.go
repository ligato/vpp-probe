package agent

import (
	"fmt"
	"os"

	"github.com/docker/docker/pkg/term"
)

var coloredOutput bool

func init() {
	if term.IsTerminal(os.Stdout.Fd()) {
		coloredOutput = true
	}
}

type Colorer interface {
	Code() string
}

func escapeClr(c Colorer, s interface{}) string {
	if !coloredOutput {
		return fmt.Sprint(s)
	}
	return fmt.Sprintf("\xff\x1b[%sm\xff%v\xff\x1b[0m\xff", c.Code(), s)
}
