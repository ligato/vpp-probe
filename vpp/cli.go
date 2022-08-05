package vpp

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"go.ligato.io/vpp-probe/probe"
	"go.ligato.io/vpp-probe/vpp/api"
)

var (
	cliShowVersionVerbose                = regexp.MustCompile(`Version:\s+(\S+)`)
	cliShowVersionVerboseCompiledBy      = regexp.MustCompile(`Compiled by:\s+(\S+)`)
	cliShowVersionVerboseCompileHost     = regexp.MustCompile(`Compile host:\s+(\S+)`)
	cliShowVersionVerboseCompileDate     = regexp.MustCompile(`Compile date:\s+(\S+)`)
	cliShowVersionVerboseCompileLocation = regexp.MustCompile(`Compile location:\s+(\S+)`)
	cliShowVersionVerboseCompiler        = regexp.MustCompile(`Compiler:\s+(\S+)`)
	cliShowVersionVerbosePID             = regexp.MustCompile(`PID:\s+([0-9]+)`)
)

// vpp# show version verbose
// Version:                  v20.09-rc0~399-gef80ad6bf~b1658
// Compiled by:              root
// Compile host:             31cb557be35c
// Compile date:             2020-09-09T11:13:09
// Compile location:         /w/workspace/vpp-merge-master-ubuntu1804
// Compiler:                 Clang/LLVM 9.0.0 (tags/RELEASE_900/final)
// Current PID:              170

type VersionVerboseData struct {
	Version         string
	CompiledBy      string
	CompileHost     string
	CompileDate     string
	CompileLocation string
	Compiler        string
	CurrentPID      string
}

func ShowVersionVerboseCLI(cli probe.CliExecutor) (*VersionVerboseData, error) {
	out, err := cli.RunCli("show version verbose")
	if err != nil {
		return nil, err
	}

	data := VersionVerboseData{}

	matchVersion := cliShowVersionVerbose.FindStringSubmatch(out)
	if len(matchVersion) > 1 {
		data.Version = matchVersion[1]
	}
	matchPid := cliShowVersionVerbosePID.FindStringSubmatch(out)
	if len(matchPid) > 1 {
		data.CurrentPID = matchPid[1]
	}
	matchCompiledBy := cliShowVersionVerboseCompiledBy.FindStringSubmatch(out)
	if len(matchCompiledBy) > 1 {
		data.CompiledBy = matchCompiledBy[1]
	}
	matchCompileHost := cliShowVersionVerboseCompileHost.FindStringSubmatch(out)
	if len(matchCompileHost) > 1 {
		data.CompiledBy = matchCompileHost[1]
	}
	matchCompileDate := cliShowVersionVerboseCompileDate.FindStringSubmatch(out)
	if len(matchCompileDate) > 1 {
		data.CompileDate = matchCompileDate[1]
	}
	matchCompileLoc := cliShowVersionVerboseCompileLocation.FindStringSubmatch(out)
	if len(matchCompileLoc) > 1 {
		data.CompileLocation = matchCompileLoc[1]
	}
	matchCompiler := cliShowVersionVerboseCompiler.FindStringSubmatch(out)
	if len(matchCompiler) > 1 {
		data.Compiler = matchCompiler[1]
	}

	return &data, nil
}

func GetPidCLI(cli probe.CliExecutor) (int, error) {
	data, err := ShowVersionVerboseCLI(cli)
	if err != nil {
		return 0, err
	}
	pid, err := strconv.Atoi(data.CurrentPID)
	if err != nil {
		return 0, err
	}
	return pid, nil
}

const (
	vppClockLayout = "Mon, 2 Jan 2006 15:04:05 MST"
)

var (
	cliShowClock = regexp.MustCompile(`Time\s+now\s+([0-9.]+),\s+([^\n]+)`)
)

// vpp# show clock
// Time now 3180.278756, Tue, 1 Dec 2020 11:52:45 GMT

/*
	Time now 7481.803097, Tue, 2 Aug 2022 7:37:38 GMT
	Time last barrier release 0.000000000
	0: Time now 7481.803110
	Thread 0 offset 0.000000000 error 0.000000000
*/

type ClockData struct {
	Uptime string
	Clock  string
}

func ShowClockCLI(cli probe.CliExecutor) (*ClockData, error) {
	out, err := cli.RunCli("show clock")
	if err != nil {
		return nil, err
	}

	data := ClockData{}

	matches := cliShowClock.FindStringSubmatch(strings.TrimSpace(out))
	if len(matches) <= 2 {
		return nil, fmt.Errorf("unable to parse input: %q", out)
	}
	if len(matches) > 1 {
		data.Uptime = matches[1]
	}
	if len(matches) > 2 {
		data.Clock = matches[2]
	}

	return &data, nil
}

func GetUptimeCLI(cli probe.CliExecutor) (time.Duration, error) {
	data, err := ShowClockCLI(cli)
	if err != nil {
		return 0, err
	}

	floatUptime, err := strconv.ParseFloat(data.Uptime, 64)
	if err != nil {
		return 0, fmt.Errorf("parse float %v error: %v", data.Uptime, err)
	}
	uptime := time.Duration(floatUptime * float64(time.Second))

	return uptime, nil
}

func GetClockCLI(cli probe.CliExecutor) (time.Time, error) {
	data, err := ShowClockCLI(cli)
	if err != nil {
		return time.Time{}, err
	}

	clock, err := time.Parse(vppClockLayout, data.Clock)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse time %v error: %v", data.Clock, err)
	}

	return clock, nil
}

func parseUptime(raw string) (time.Duration, error) {
	matches := cliShowClock.FindStringSubmatch(raw)
	if len(matches) <= 1 {
		return 0, fmt.Errorf("invalid input: %q", raw)
	}
	rawUptime := matches[1]
	floatUptime, err := strconv.ParseFloat(rawUptime, 64)
	if err != nil {
		return 0, fmt.Errorf("parse float %v error: %v", rawUptime, err)
	}
	return time.Duration(floatUptime * float64(time.Second)), nil
}

func parseClock(raw string) (time.Time, error) {
	matches := cliShowClock.FindStringSubmatch(raw)
	if len(matches) <= 2 {
		return time.Time{}, fmt.Errorf("invalid input: %q", raw)
	}
	rawClock := matches[2]
	clock, err := time.Parse(vppClockLayout, rawClock)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse time %v error: %v", rawClock, err)
	}
	return clock, nil
}

var (
// TODO: parse log entries from CLI
//cliShowLog = regexp.MustCompile(``)
)

// vpp# show log
// 2020/12/01 10:59:44:837 notice     plugin/load    Loaded plugin: abf_plugin.so (Access Control List (ACL) Based Forwarding)
// 2020/12/01 10:59:44:841 notice     plugin/load    Loaded plugin: acl_plugin.so (Access Control Lists (ACL))
// 2020/12/01 10:59:44:841 notice     plugin/load    Loaded plugin: adl_plugin.so (Allow/deny list plugin)
// 2020/12/01 10:59:44:843 notice     plugin/load    Loaded plugin: avf_plugin.so (Intel Adaptive Virtual Function (AVF) Device
// ...

func DumpLogsCLI(cli probe.CliExecutor) ([]string, error) {
	out, err := cli.RunCli("show log")
	if err != nil {
		return nil, err
	}
	logs := strings.Split(out, "\n")
	return logs, nil
}

func ShowPluginsCLI(cli probe.CliExecutor) ([]api.Plugin, error) {
	const (
		pluginPathPrefix = "Plugin path is:"
		pluginNameSuffix = "_plugin.so"
	)

	out, err := cli.RunCli("show plugins")
	if err != nil {
		return nil, err
	}

	lines := strings.Split(out, "\n")
	if len(lines) == 0 {
		return nil, fmt.Errorf("empty output for 'show plugins'")
	}
	pluginPathLine := strings.TrimSpace(lines[0])
	if !strings.HasPrefix(pluginPathLine, pluginPathPrefix) {
		return nil, fmt.Errorf("unexpected output for 'show plugins'")
	}
	pluginPath := strings.TrimSpace(strings.TrimPrefix(pluginPathLine, pluginPathPrefix))
	if len(pluginPath) == 0 {
		return nil, fmt.Errorf("plugin path not found in output for 'show plugins'")
	}

	var plugins []api.Plugin
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		var i int
		if _, err := fmt.Sscanf(fields[0], "%d.", &i); err != nil {
			continue
		}
		if i <= 0 {
			continue
		}
		plugin := api.Plugin{
			Name:        strings.TrimSuffix(fields[1], pluginNameSuffix),
			Path:        fields[1],
			Version:     fields[2],
			Description: strings.Join(fields[3:], " "),
		}
		plugins = append(plugins, plugin)
	}

	return plugins, nil
}
