package vpp

import (
	"regexp"
	"strconv"

	"go.ligato.io/vpp-probe/pkg/vppcli"
	"go.ligato.io/vpp-probe/vpp/types"
)

var (
	cliShowVersionVerbose    = regexp.MustCompile(`Version:\s+(\S+)`)
	cliShowVersionVerbosePID = regexp.MustCompile(`PID:\s+([0-9]+)`)
)

func GetVersionInfoCLI(cli vppcli.Executor) (*types.VersionInfo, error) {
	out, err := cli.RunCli("show version verbose")
	if err != nil {
		return nil, err
	}

	info := &types.VersionInfo{}

	matchVersion := cliShowVersionVerbose.FindStringSubmatch(out)
	if len(matchVersion) > 1 {
		info.Version = matchVersion[1]
	}

	matchPid := cliShowVersionVerbosePID.FindStringSubmatch(out)
	if len(matchPid) > 1 {
		info.Pid, _ = strconv.Atoi(matchPid[1])
	}

	return info, nil
}

func GetClockCLI(cli vppcli.Executor) (string, error) {
	clock, err := cli.RunCli("show clock")
	if err != nil {
		return "", err
	}

	return clock, nil
}
