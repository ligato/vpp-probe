package kube

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"

	"go.ligato.io/vpp-probe/pkg/exec"
	"go.ligato.io/vpp-probe/providers/kube/client"
)

type podCommand struct {
	Cmd  string
	Args []string

	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer

	pod *client.Pod
}

func (c *podCommand) SetStdin(in io.Reader) exec.Cmd {
	c.Stdin = in
	return c
}

func (c *podCommand) SetStdout(out io.Writer) exec.Cmd {
	c.Stdout = out
	return c
}

func (c *podCommand) SetStderr(out io.Writer) exec.Cmd {
	c.Stderr = out
	return c
}

func (c *podCommand) Output() ([]byte, error) {
	if c.Stdout != nil {
		return nil, errors.New("stdout already set")
	}
	var stdout, stderr bytes.Buffer
	c.Stdout = &stdout

	captureErr := c.Stderr == nil
	if captureErr {
		c.Stderr = &stderr
	}

	err := c.Run()
	if err != nil && captureErr {
		command := fmt.Sprintf("%q %q", c.Cmd, c.Args)
		err = fmt.Errorf("pod exec %v error %w: %s", command, err, stderr.Bytes())
	}
	return stdout.Bytes(), err
}

func (c *podCommand) Run() error {
	command := fmt.Sprintf("%s %s", c.Cmd, strings.Join(c.Args, " "))
	return c.pod.Exec(command, c.Stdin, c.Stdout, c.Stderr)
}
