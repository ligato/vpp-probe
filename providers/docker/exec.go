package docker

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"

	docker "github.com/fsouza/go-dockerclient"
	"github.com/sirupsen/logrus"

	"go.ligato.io/vpp-probe/pkg/exec"
)

type command struct {
	Cmd  string
	Args []string

	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer

	container *ContainerHandler
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
		err = fmt.Errorf("container exec %w: %s", err, stderr.Bytes())
	}
	return stdout.Bytes(), err
}

func (c *command) Run() error {
	command := fmt.Sprintf("%s %s", c.Cmd, strings.Join(c.Args, " "))

	logrus.Tracef("container %s executing command %v", c.container.container.ID, command)

	err := containerExec(c.container.client, c.container.container.ID, command, c.Stdin, c.Stdout, c.Stderr)
	if err != nil {
		logrus.Tracef("container %s command failed: %v", c.container.container.ID, err)
		return err
	}
	logrus.Tracef("container %s command succeeded", c.container.container.ID)

	return nil
}

func containerExec(client *docker.Client, containerID string, command string, stdin io.Reader, stdout, stderr io.Writer) error {
	createOpts := docker.CreateExecOptions{
		Container:    containerID,
		Cmd:          []string{"sh", "-c", command},
		AttachStdin:  stdin != nil,
		AttachStdout: stdout != nil,
		AttachStderr: stderr != nil,
		Tty:          false,
		Env:          nil,
		Context:      nil,
		Privileged:   false,
	}
	exe, err := client.CreateExec(createOpts)
	if err != nil {
		return err
	}
	startOpts := docker.StartExecOptions{
		InputStream:  stdin,
		OutputStream: stdout,
		ErrorStream:  stderr,
		Detach:       false,
		Tty:          false,
		RawTerminal:  false,
		Success:      nil,
		Context:      nil,
	}
	if err := client.StartExec(exe.ID, startOpts); err != nil {
		return err
	}
	inspect, err := client.InspectExec(exe.ID)
	logrus.Tracef("inspect exec: %+v", inspect)
	if err != nil {
		return err
	} else if inspect.ExitCode != 0 {
		return fmt.Errorf("docker exec command '%v' failed (exit code %d)", command, inspect.ExitCode)
	}
	return nil
}
