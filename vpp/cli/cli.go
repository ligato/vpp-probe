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
)

var (
	// Local provides default access to the VPP CLI via vppctl.
	Local = NewCmdExecutor("/usr/bin/vppctl")
)

// VppCtlAddr returns vppctl handler that
func VppCtlAddr(addr string) Executor {
	return NewCmdExecutor("/usr/bin/vppctl", "-s", addr)
}

// Executor defines method executing VPP CLI commands.
type Executor interface {
	RunCli(cmd string) (string, error)
}

// ExecutorFunc is a helper type for implementing the Executor from function.
type ExecutorFunc func(cmd string) (string, error)

func (f ExecutorFunc) RunCli(cmd string) (string, error) {
	return f(cmd)
}

// CleanOutput cleans the CLI output received from VPP:
// - converts line endings to (CR LF -> LF)
// - trim leading newlines (CR/LF)
// - strips banner until the prompt  (one of random VPP bugs)
func CleanOutput(out []byte) string {
	const promptChar = `vpp# `
	o := bytes.ReplaceAll(out, []byte("\r\n"), []byte("\n"))
	o = bytes.TrimLeft(o, "\r\n")
	if prompt := bytes.Index(o, []byte(promptChar)); prompt > 0 {
		o = o[prompt+len(promptChar):]
	}
	return string(o)
}
