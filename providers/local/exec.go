package local

import (
	"fmt"
	"io"
	stdexec "os/exec"
)

type Cmd struct {
	*stdexec.Cmd
}

func (c *Cmd) SetStdin(in io.Reader) {
	c.Stdin = in
}

func (c *Cmd) SetStdout(out io.Writer) {
	c.Stdout = out
}

func (c *Cmd) SetStderr(out io.Writer) {
	c.Stderr = out
}

func (c *Cmd) Output() ([]byte, error) {
	out, err := c.Cmd.Output()
	if err != nil {
		return out, fmt.Errorf("command '%v' %w", c, includeStderr(err))
	}
	return out, nil
}

func (c *Cmd) Run() error {
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
