package vpp

import (
	"regexp"
	"strconv"

	"go.ligato.io/vpp-probe/client"
	"go.ligato.io/vpp-probe/pkg/vppcli"
)

var (
	cliShowVersionVerbose    = regexp.MustCompile(`Version:\s+(\S+)`)
	cliShowVersionVerbosePID = regexp.MustCompile(`PID:\s+([0-9]+)`)
)

func GetVersionInfoCLI(cli vppcli.Handler) (*client.VersionInfo, error) {
	out, err := cli.RunCli("show version verbose")
	if err != nil {
		return nil, err
	}

	info := &client.VersionInfo{}

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

func GetClockCLI(cli vppcli.Handler) (string, error) {
	clock, err := cli.RunCli("show clock")
	if err != nil {
		return "", err
	}

	return clock, nil
}
