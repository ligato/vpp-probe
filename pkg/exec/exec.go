package exec

import (
	"bytes"
	"io"
)

// Interface is a generic interface for creating commands.
type Interface interface {
	Command(cmd string, args ...string) Cmd
}

// Cmd is an interface for a command to be executed.
type Cmd interface {
	Run() error
	Output() ([]byte, error)

	SetStdin(in io.Reader)
	SetStdout(out io.Writer)
	SetStderr(out io.Writer)
	// TODO: SetEnv
}

func Output(cmd Cmd) ([]byte, error) {
	var stdout bytes.Buffer
	cmd.SetStdout(&stdout)
	err := cmd.Run()
	return stdout.Bytes(), err
}
