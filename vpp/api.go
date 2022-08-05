package vpp

import (
	"time"

	"github.com/sirupsen/logrus"

	"go.ligato.io/vpp-probe/vpp/api"
	"go.ligato.io/vpp-probe/vpp/binapi"
)

const versionCompileDateLayout = "2006-01-02T15:04:05"

func (v *Instance) GetVersion() (string, error) {
	if v.api != nil {
		data, err := binapi.ShowVersion(v.api)
		if err != nil {
			logrus.Debugf("getting version via API failed: %v", err)
		} else {
			return data.Version, nil
		}
	}

	versionData, err := ShowVersionVerboseCLI(v.cli)
	if err != nil {
		return "", err
	}

	return versionData.Version, nil
}

func (v *Instance) GetBuildInfo() (*api.BuildInfo, error) {
	if v.api != nil {
		data, err := binapi.ShowVersion(v.api)
		if err != nil {
			logrus.Debugf("getting version via API failed: %v", err)
		} else {
			buildDate, _ := time.Parse(versionCompileDateLayout, data.BuildDate)
			versionInfo := api.BuildInfo{
				Version:       data.Version,
				BuildDate:     buildDate,
				BuildLocation: data.BuildDirectory,
			}
			return &versionInfo, nil
		}
	}

	versionData, err := ShowVersionVerboseCLI(v.cli)
	if err != nil {
		return nil, err
	}

	buildDate, _ := time.Parse(versionCompileDateLayout, versionData.CompileDate)

	versionInfo := api.BuildInfo{
		Version:       versionData.Version,
		BuildUser:     versionData.CompiledBy,
		BuildHost:     versionData.CompileHost,
		BuildDate:     buildDate,
		BuildLocation: versionData.CompileLocation,
		Compiler:      versionData.Compiler,
	}

	return &versionInfo, nil
}

func (v *Instance) GetSystemInfo() (*api.RuntimeInfo, error) {
	var sysInfo api.RuntimeInfo

	if v.api != nil {
		pid, err := binapi.GetPIDChan(v.api)
		if err != nil {
			logrus.Debugf("getting pid via API failed: %v", err)
		} else {
			sysInfo.Pid = pid
		}
	}
	if sysInfo.Pid == 0 {
		pid, err := GetPidCLI(v.cli)
		if err != nil {
			return nil, err
		} else {
			sysInfo.Pid = pid
		}
	}

	if uptime, err := GetUptimeCLI(v.cli); err != nil {
		logrus.Debugf("getting uptime via CLI failed: %v", err)
	} else {
		sysInfo.Uptime = api.Uptime(uptime / time.Second) //uint64(uptime / time.Second)
	}
	if clock, err := GetClockCLI(v.cli); err != nil {
		logrus.Debugf("getting clock via CLI failed: %v", err)
	} else {
		sysInfo.Clock = &clock
	}

	return &sysInfo, nil
}

func (v *Instance) ListInterfaces() ([]*api.Interface, error) {
	if v.api != nil {
		return binapi.ListInterfacesChan(v.api)
	}
	return nil, ErrAPIUnavailable
}

func (v *Instance) GetUptime() (time.Duration, error) {
	// uptime not available via binary API

	return GetUptimeCLI(v.cli)
}

func (v *Instance) DumpLogs() ([]string, error) {
	if v.api != nil {
		return binapi.DumpLogsChan(v.api)
	}
	return DumpLogsCLI(v.cli)
}

func (v *Instance) GetLogs(since time.Time) ([]string, error) {
	if v.api != nil {
		return binapi.DumpLogsSinceChan(v.api, since)
	}
	return DumpLogsCLI(v.cli)
}

func (v *Instance) ListStats() ([]string, error) {
	if v.stats == nil {
		return nil, ErrStatsUnavailable
	}
	return ListStats(v.stats)
}

func (v *Instance) DumpStats() (*api.VppStats, error) {
	if v.stats == nil {
		return nil, ErrStatsUnavailable
	}
	return DumpStats(v.stats)
}
