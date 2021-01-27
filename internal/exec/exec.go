package exec

import (
	"io"
)

type Interface interface {
	Command(cmd string, args ...string) Cmd
}

type Cmd interface {
	Run() error
	Output() ([]byte, error)

	SetStdin(in io.Reader)
	SetStdout(out io.Writer)
	SetStderr(out io.Writer)
}

type Wrapper struct {
	Interface

	cmd  string
	args []string
}

func Wrap(e Interface, cmd string, args ...string) *Wrapper {
	return &Wrapper{
		Interface: e,
		cmd:       cmd,
		args:      args,
	}
}

func (w *Wrapper) Command(cmd string, args ...string) Cmd {
	args = append([]string{cmd}, args...)
	return w.Interface.Command(w.cmd, append(w.args, args...)...)
}
