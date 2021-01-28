package exec

import (
	"fmt"
	"io"
	stdexec "os/exec"
)

func Command(cmd string, args ...string) Cmd {
	return (&Local{}).Command(cmd, args...)
}

type Local struct{}

func (l *Local) Command(cmd string, args ...string) Cmd {
	return &LocalCmd{
		Cmd: stdexec.Command(cmd, args...),
	}
}

type LocalCmd struct {
	*stdexec.Cmd
}

func (c *LocalCmd) SetStdin(in io.Reader) {
	c.Stdin = in
}

func (c *LocalCmd) SetStdout(out io.Writer) {
	c.Stdout = out
}

func (c *LocalCmd) SetStderr(out io.Writer) {
	c.Stderr = out
}

func (c *LocalCmd) Output() ([]byte, error) {
	out, err := c.Cmd.Output()
	if err != nil {
		return out, fmt.Errorf("command '%v' %v", c, includeStderr(err))
	}
	return out, nil
}

func (c *LocalCmd) Run() error {
	return c.Cmd.Run()
}

func includeStderr(err error) error {
	if err != nil {
		if ee, ok := err.(*stdexec.ExitError); ok {
			return fmt.Errorf("%w: %s", err, ee.Stderr)
		}
	}
	return err
}
