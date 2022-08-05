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
