// Package exec contains abstract interface for executing commands.
package exec

import (
	"bytes"
	"io"
)

// Interface is a generic interface for creating commands.
type Interface interface {
	Command(cmd string, args ...string) Cmd
	// TODO: CommandContext
}

// Cmd is an interface for a command to be executed.
type Cmd interface {
	Run() error
	Output() ([]byte, error)

	SetStdin(in io.Reader) Cmd
	SetStdout(out io.Writer) Cmd
	SetStderr(out io.Writer) Cmd
	// TODO: SetEnv
}

// Command returns a local command.
func Command(cmd string, args ...string) Cmd {
	return (&LocalCmder{}).Command(cmd, args...)
}

func Output(cmd Cmd) ([]byte, error) {
	var stdout bytes.Buffer
	err := cmd.SetStdout(&stdout).Run()
	return stdout.Bytes(), err
}

/*type CommonCmd struct {
	Command  string
	Args []string

	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer

	Cmd
}

func (c *CommonCmd) SetStdin(in io.Reader)  {
	c.Stdin = in
}

func (c *CommonCmd) SetStdout(out io.Writer)  {
	c.Stdout = out
}

func (c *CommonCmd) SetStderr(out io.Writer) {
	c.Stderr = out
}

func Output2(c CommonCmd) ([]byte, error) {
	if c.Stdout != nil {
		return nil, errors.New("stdout already set")
	}
	var stdout, stderr bytes.Buffer
	c.SetStdout(&stdout)

	captureErr := c.Stderr == nil
	if captureErr {
		c.SetStderr( &stderr)
	}

	err := c.Run()
	if err != nil && captureErr {
		command := fmt.Sprintf("%q %q", c.Cmd, c.Args)
		err = fmt.Errorf("pod exec %v error %w: %s", command, err, stderr.Bytes())
	}
	return stdout.Bytes(), err
}*/
