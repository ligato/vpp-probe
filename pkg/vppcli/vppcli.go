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
	"context"
	"fmt"
	"os/exec"
	"strings"

	"git.fd.io/govpp.git/api"
	"git.fd.io/govpp.git/examples/binapi/vpe"
	"github.com/sirupsen/logrus"
)

var Default = VppCtl()

func Run(cmd string) (string, error) {
	return Default.RunCli(cmd)
}

type CLI interface {
	RunCli(cmd string) (string, error)
}

func VppCtl() CLI {
	return &cliCommand{
		cmd: "/usr/bin/vppctl",
	}
}

func KubeCtl(args ...string) CLI {
	return &cliCommand{
		cmd:  "kubectl",
		args: args,
	}
}

type cliCommand struct {
	cmd  string
	args []string
}

func (ctx *cliCommand) RunCli(cmd string) (string, error) {
	logrus.Debugf("command CLI: %q", cmd)

	args := make([]string, len(ctx.args)+1)
	for i, a := range ctx.args {
		args[i] = a
	}
	args = append(args, cmd)

	c := exec.Command(ctx.cmd, args...)

	// STDIN annot be used for vppctl because it will
	// fail with error "failed: broken pipe" and exit code 141
	//c.Stdin = strings.NewReader(cmd)

	out, err := c.Output()
	if err != nil {
		return string(out), fmt.Errorf("command CLI '%v' failed: %v %s", c, err, out)
	}

	reply := string(bytes.ReplaceAll(out, []byte("\r\n"), []byte("\n")))
	logrus.Debugf("CLI command reply: %q", reply)

	if prompt := strings.Index(reply, `vpp# `); prompt > 0 {
		reply = reply[prompt+5:]
	}
	return reply, nil
}

func BinapiCLI(ch api.Channel) CLI {
	return &cliBinapi{
		vpeRPC: vpe.NewServiceClient(ch),
	}
}

type cliBinapi struct {
	vpeRPC vpe.RPCService
}

func (ctx *cliBinapi) RunCli(cmd string) (string, error) {
	logrus.Debugf("binapi CLI: %q", cmd)

	reply, err := ctx.vpeRPC.CliInband(context.Background(), &vpe.CliInband{
		Cmd: cmd,
	})
	if err != nil {
		return "", fmt.Errorf("binapi CLI '%v' failed: %v", cmd, err)
	}
	logrus.Debugf("binapi CLI reply: %s", reply.Reply)
	return reply.Reply, api.RetvalToVPPApiError(reply.Retval)
}
