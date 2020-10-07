package vpp

import (
	"fmt"

	govppapi "git.fd.io/govpp.git/api"
	"github.com/sirupsen/logrus"

	"go.ligato.io/vpp-probe/pkg/vppcli"
	"go.ligato.io/vpp-probe/probe"
	"go.ligato.io/vpp-probe/vpp/types"
)

// Instance is an instance of probed VPP accessed via probe.Handler.
type Instance struct {
	handler probe.Handler

	info *types.VersionInfo

	cli   vppcli.Executor
	ch    govppapi.Channel
	stats govppapi.StatsProvider
}

func NewInstance(handler probe.Handler) *Instance {
	return &Instance{
		handler: handler,
	}
}

func (v *Instance) ID() string {
	return v.handler.Name()
}

func (v *Instance) VersionInfo() *types.VersionInfo {
	return v.info
}

func (v *Instance) Init() (err error) {
	logrus.Debugf("init instance %v", v.ID())

	v.cli, err = v.handler.GetCLI()
	if err != nil {
		return fmt.Errorf("CLI error: %v", err)
	}
	v.info, err = v.getVersionInfo()
	if err != nil {
		return err
	}

	if err := v.initBinapi(); err != nil {
		logrus.Warnf("binapi init error: %v", err)
	}
	if err := v.initStats(); err != nil {
		logrus.Warnf("stats init error: %v", err)
	}

	return nil
}

func (v *Instance) RunCli(cmd string) (string, error) {
	if v.cli == nil {
		return "", fmt.Errorf("CLI unavailable")
	}
	return v.cli.RunCli(cmd)
}

func (v *Instance) getVersionInfo() (*types.VersionInfo, error) {
	return GetVersionInfoCLI(v.cli)
}

func (v *Instance) initBinapi() error {
	ch, err := v.handler.GetAPI()
	if err != nil {
		return err
	}
	if err := checkCompatibility(ch); err != nil {
		return err
	}
	v.ch = ch
	return nil
}

func (v *Instance) initStats() error {
	stats, err := v.handler.GetStats()
	if err != nil {
		return err
	}
	var sysStats govppapi.SystemStats
	if err := stats.GetSystemStats(&sysStats); err != nil {
		return fmt.Errorf("stats unavailable: %v", err)
	}
	v.stats = stats
	return nil
}

func (v *Instance) ListInterfaces() ([]*types.Interface, error) {
	return ListInterfaces(v.ch)
}

func (v *Instance) GetClock() (string, error) {
	return GetClockCLI(v.cli)
}

func (v *Instance) DumpLogs() ([]string, error) {
	return DumpLogs(v.ch)
}
