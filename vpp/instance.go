package vpp

import (
	"context"
	"fmt"
	"runtime/debug"
	"strings"

	govppapi "git.fd.io/govpp.git/api"
	"github.com/sirupsen/logrus"
	"go.ligato.io/vpp-agent/v3/plugins/govppmux/vppcalls"
	"go.ligato.io/vpp-agent/v3/plugins/vpp/binapi"

	"go.ligato.io/vpp-probe/probe"
	"go.ligato.io/vpp-probe/vpp/api"
	vppcli "go.ligato.io/vpp-probe/vpp/cli"
)

// Instance handles access to a running VPP instance.
type Instance struct {
	probe *probe.Probe

	vppClient *vppClient
	cli       vppcli.Executor
	api       govppapi.Channel
	stats     govppapi.StatsProvider

	status *APIStatus
	info   *api.VersionInfo
}

// NewInstance tries to initialize probe and returns a new Instance on success.
func NewInstance(probe *probe.Probe) (*Instance, error) {
	h := &Instance{
		probe:     probe,
		vppClient: newVppClient(),
		status:    &APIStatus{},
	}
	return h, h.Init()
}

func (v *Instance) ID() string {
	//return v.probe.String()
	return fmt.Sprintf("vpp::%s", v.probe.String())
}

func (v *Instance) Status() *APIStatus {
	return v.status
}

func (v *Instance) Probe() *probe.Probe {
	return v.probe
}

func (v *Instance) VersionInfo() *api.VersionInfo {
	return v.info
}

func (v *Instance) Init() (err error) {
	logrus.Debugf("init probe %v", v.ID())

	if err = v.init(); err != nil {
		v.status.LastErr = err
		return err
	}

	v.info, err = v.GetVersionInfo()
	if err != nil {
		v.status.LastErr = err
		return err
	}

	return nil
}

func (v *Instance) init() (err error) {
	if err = v.initCLI(); err != nil {
		v.status.CLI.SetError(err)
		logrus.Warnf("CLI init error: %v", err)
		return err
	} else {
		v.status.CLI.State = StateOK
	}

	if err := v.initBinapi(); err != nil {
		v.status.BinAPI.SetError(err)
		logrus.Warnf("Binary API init error: %v", err)
	} else {
		v.status.BinAPI.State = StateOK
	}

	if err := v.initStats(); err != nil {
		v.status.StatsAPI.SetError(err)
		logrus.Warnf("Stats API init error: %v", err)
	} else {
		v.status.StatsAPI.State = StateOK
	}

	return nil
}

func (v *Instance) initCLI() error {
	cli, err := v.probe.GetCLI()
	if err != nil {
		return err
	}
	v.cli = cli
	return nil
}

func (v *Instance) initBinapi() (err error) {
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("recovered panic: %v", e)
			logrus.WithError(err).Errorf("recovered panic:\n%s\n", string(debug.Stack()))
		}
	}()

	ch, err := v.probe.GetAPI()
	if err != nil {
		return err
	}
	v.vppClient.ch = ch

	v.vppClient.version, err = binapi.CompatibleVersion(ch)
	if err != nil {
		logrus.Warnf("binapi.CompatibleVersion error: %v", err)
	}

	info, err := v.GetVersionInfo()
	if err != nil {
		logrus.Warnf("GetVersionInfo error: %v", err)
	}
	for version := range binapi.Versions {
		ver := version
		if len(ver) > 5 {
			ver = ver[:5]
		}
		logrus.Debugf("checking version %v in %q", ver, info.Version)
		if strings.Contains(info.Version, string(ver)) {
			v.vppClient.version = version
			logrus.Debugf("found version %v in %q", ver, info.Version)
			break
		}
	}

	// register binapi messages to gob package (required for proxy)
	/*msgList, ok := binapi.Versions[v.vppClient.BinapiVersion()]
	if !ok {
		return fmt.Errorf("not found version %v", v.vppClient.BinapiVersion())
	}
	for _, msg := range msgList.AllMessages() {
		gob.Register(msg)
	}*/

	v.vppClient.vpp, err = vppcalls.NewHandler(v.vppClient)
	if err != nil {
		return fmt.Errorf("no compatible VPP handler found: %v", err)
	}

	v.api = ch
	return nil
}

func (v *Instance) initStats() error {
	stats, err := v.probe.GetStats()
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

func (v *Instance) RunCli(cmd string) (string, error) {
	return v.cli.RunCli(cmd)
	if v.vppClient.vpp != nil {
		return v.vppClient.vpp.RunCli(context.Background(), cmd)
	}
	if v.cli == nil {
		return "", ErrCLIUnavailable
	}
	return v.cli.RunCli(cmd)
}
