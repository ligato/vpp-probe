//  Copyright (c) 2020 Cisco and/or its affiliates.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at:
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

package vppcli

import (
	"bytes"
	"fmt"
	"os/exec"

	"github.com/sirupsen/logrus"
)

var (
	// Local provides default access to the VPP CLI via vppctl.
	Local = ExecCmd("/usr/bin/vppctl")
)

// Run executes a CLI command using Local handler.
func Run(cmd string) (string, error) {
	return Local.RunCli(cmd)
}

// VppCtl returns vppctl handler that
func VppCtl(addr string) Handler {
	return ExecCmd("/usr/bin/vppctl", "-s", addr)
}

// Handler defines method executing VPP CLI commands.
type Handler interface {
	RunCli(cmd string) (string, error)
}

// HandlerFunc is a helper type for simpler implementation of the Handler.
type HandlerFunc func(cmd string) (string, error)

func (f HandlerFunc) RunCli(cmd string) (string, error) {
	return f(cmd)
}

// Command provides access to VPP CLI via external process.
type Command struct {
	Cmd  string
	Args []string
}

// ExecCmd returns a new Command.
func ExecCmd(cmd string, args ...string) *Command {
	return &Command{
		Cmd:  cmd,
		Args: args,
	}
}

// RunCli executes CLI command and returns the response or error.
func (ctx *Command) RunCli(cmd string) (string, error) {
	logrus.Debugf("command CLI: %q", cmd)

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
		return string(out), fmt.Errorf("command CLI '%v' failed (%v): %s", c, err, out)
	}
	logrus.Tracef("CLI command reply: %q", out)

	reply := CleanOutput(out)
	return reply, nil
}

const vppPrompt = `vpp# `

// CleanOutput cleans an output received from VPP CLI.
func CleanOutput(out []byte) string {
	// convert line endings
	reply := bytes.ReplaceAll(out, []byte("\r\n"), []byte("\n"))
	// trim leading newlines
	reply = bytes.TrimLeft(reply, "\r\n")
	// strip banner until prompt
	if prompt := bytes.Index(reply, []byte(vppPrompt)); prompt > 0 {
		reply = reply[prompt+len(vppPrompt):]
	}
	return string(reply)
}
