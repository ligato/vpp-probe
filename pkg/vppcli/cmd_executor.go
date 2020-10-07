package vppcli

import (
	"fmt"
	"os/exec"

	"github.com/sirupsen/logrus"
)

// CmdExecutor provides access to CLI by executing it via external command.
type CmdExecutor struct {
	Cmd  string
	Args []string
}

// NewCmdExecutor returns a new CmdExecutor.
func NewCmdExecutor(cmd string, args ...string) *CmdExecutor {
	return &CmdExecutor{
		Cmd:  cmd,
		Args: args,
	}
}

// RunCli executes CLI command and returns the response or error.
func (ctx *CmdExecutor) RunCli(cmd string) (string, error) {
	logrus.Tracef("run CLI command: %q", cmd)

	args := make([]string, len(ctx.Args)+1)
	for i, a := range ctx.Args {
		args[i] = a
	}
	args = append(args, cmd)

	c := exec.Command(ctx.Cmd, args...)

	// STDIN annot be used for vppctl because it will
	// fail with error "failed: broken pipe" and exit code 141
	//c.Stdin = strings.NewReader(cmd)

	out, err := c.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			out = ee.Stderr
		}
		return string(out), fmt.Errorf("CLI command '%v' failed (%v): %s", c, err, out)
	}
	logrus.Tracef("CLI command output: %q", out)

	reply := CleanOutput(out)
	return reply, nil
}
