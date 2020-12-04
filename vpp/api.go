package vpp

import (
	"time"

	"github.com/sirupsen/logrus"

	"go.ligato.io/vpp-probe/vpp/api"
	"go.ligato.io/vpp-probe/vpp/binapi"
)

func (v *Instance) GetVersionInfo() (*api.VersionInfo, error) {
	if v.api != nil {
		versionInfo, err := binapi.GetVersionInfo(v.api)
		if err != nil {
			logrus.Warnf("getting version via API failed: %v", err)
		} else {
			return versionInfo, nil
		}
	}
	return GetVersionInfoCLI(v.cli)
}

func (v *Instance) ListInterfaces() ([]*api.Interface, error) {
	if v.api != nil {
		return binapi.ListInterfaces(v.api)
	}
	return nil, ErrAPIUnavailable
}

func (v *Instance) GetUptime() (time.Duration, error) {
	// uptime not available via binary API

	return GetUptimeCLI(v.cli)
}

func (v *Instance) DumpLogs() ([]string, error) {
	if v.api != nil {
		return binapi.DumpLogs(v.api)
	}
	return DumpLogsCLI(v.cli)
}

func (v *Instance) GetLogs(since time.Time) ([]string, error) {
	if v.api != nil {
		return binapi.DumpLogsSince(v.api, since)
	}
	return DumpLogsCLI(v.cli)
}

func (v *Instance) ListStats() ([]string, error) {
	if v.stats == nil {
		return nil, ErrStatsUnavailable
	}
	return ListStats(v.stats)
}
