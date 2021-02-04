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

type command struct {
	Cmd  string
	Args []string

	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer

	pod *client.Pod
}

func (c *command) SetStdin(in io.Reader) exec.Cmd {
	c.Stdin = in
	return c
}

func (c *command) SetStdout(out io.Writer) exec.Cmd {
	c.Stdout = out
	return c
}

func (c *command) SetStderr(out io.Writer) exec.Cmd {
	c.Stderr = out
	return c
}

func (c *command) Output() ([]byte, error) {
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
		command := fmt.Sprintf("%s %s", c.Cmd, strings.Join(c.Args, " "))
		err = fmt.Errorf("command %q error %w: %s", command, err, stderr.Bytes())
	}
	return stdout.Bytes(), err
}

func (c *command) Run() error {
	command := fmt.Sprintf("%s %s", c.Cmd, strings.Join(c.Args, " "))
	return c.pod.Exec(command, c.Stdin, c.Stdout, c.Stderr)
}
