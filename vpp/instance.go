// Package vpp handles the VPP instance.
package vpp

import (
	"encoding/gob"
	"encoding/json"
	"fmt"
	"runtime/debug"
	"strings"

	govppapi "git.fd.io/govpp.git/api"
	"github.com/sirupsen/logrus"
	"go.ligato.io/vpp-agent/v3/plugins/vpp/binapi"

	"go.ligato.io/vpp-probe/pkg/exec"
	"go.ligato.io/vpp-probe/probe"
	"go.ligato.io/vpp-probe/vpp/agent"
	"go.ligato.io/vpp-probe/vpp/api"
	vppcli "go.ligato.io/vpp-probe/vpp/cli"
)

// Instance handles access to a running VPP instance.
type Instance struct {
	handler probe.Handler

	cli   probe.CliExecutor
	api   govppapi.Channel
	stats govppapi.StatsProvider

	agent *agent.Instance

	status *APIStatus
	info   api.VersionInfo
}

func (v *Instance) MarshalJSON() ([]byte, error) {
	type instanceData struct {
		ID       string
		Metadata map[string]string
		Info     api.VersionInfo
		Status   *APIStatus
		Agent    *agent.Instance
	}
	instance := instanceData{
		ID:       v.handler.ID(),
		Metadata: v.handler.Metadata(),
		Info:     v.info,
		Agent:    v.agent,
		Status:   v.status,
	}
	return json.Marshal(instance)
}

// NewInstance tries to initialize probe and returns a new Instance on success.
func NewInstance(probe probe.Handler) (*Instance, error) {
	h := &Instance{
		handler: probe,
		status:  &APIStatus{},
	}
	return h, h.Init()
}

func (v *Instance) ID() string {
	return fmt.Sprintf("vpp::%s", v.handler.ID())
}

func (v *Instance) Status() *APIStatus {
	return v.status
}

func (v *Instance) Handler() probe.Handler {
	return v.handler
}

func (v *Instance) Agent() *agent.Instance {
	return v.agent
}

func (v *Instance) VersionInfo() api.VersionInfo {
	return v.info
}

func (v *Instance) Init() (err error) {
	logrus.Tracef("init vpp instance: %v", v.ID())

	if err = v.initVPP(); err != nil {
		v.status.LastErr = err
		return err
	}

	if err = v.initAgent(); err != nil {
		logrus.Debugf("vpp agent not detected")
	}

	info, err := v.GetVersionInfo()
	if err != nil {
		v.status.LastErr = err
		return err
	}
	v.info = *info

	return nil
}

func (v *Instance) RunCli(cmd string) (string, error) {
	if v.cli == nil {
		return "", ErrCLIUnavailable
	}
	return v.cli.RunCli(cmd)
}

func (v *Instance) initAgent() error {
	a, err := agent.NewInstance(v.handler)
	if err != nil {
		return err
	}
	v.agent = a
	return nil
}

func (v *Instance) initVPP() (err error) {
	if err = v.initCLI(); err != nil {
		v.status.CLI.SetError(err)
		return err
	} else {
		v.status.CLI.State = StateOK
	}

	if err := v.initBinapi(); err != nil {
		v.status.BinAPI.SetError(err)
		logrus.Debugf("Binary API init error: %v", err)
	} else {
		v.status.BinAPI.State = StateOK
	}

	if err := v.initStats(); err != nil {
		v.status.StatsAPI.SetError(err)
		logrus.Debugf("Stats API init error: %v", err)
	} else {
		v.status.StatsAPI.State = StateOK
	}

	return nil
}

const (
	defaultCliSocket = "/run/vpp/cli.sock"
	defaultCliAddr   = "localhost:5002"
)

func (v *Instance) initCLI() error {
	var args []string
	if _, err := v.handler.Command("ls", defaultCliSocket).Output(); err != nil {
		args = append(args, "-s", defaultCliAddr)
		logrus.Tracef("checking cli socket error: %v, using flag '%s' for vppctl", err, args)
	}
	wrapper := exec.Wrap(v.handler, "/usr/bin/vppctl", args...)
	cli := vppcli.ExecutorFunc(func(cmd string) (string, error) {
		c := `"` + cmd + `"`
		out, err := wrapper.Command(c).Output()
		if err != nil {
			return "", err
		}
		return string(out), nil
	})

	/*cli, err := v.handler.GetCLI()
	if err != nil {
		return fmt.Errorf("CLI handler: %w", err)
	}*/

	out, err := cli.RunCli("show version verbose")
	if err != nil {
		return fmt.Errorf("CLI version check: %w", err)
	}
	logrus.Tracef("VPP version:\n%v", out)

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

	vppClient := newVppClient()
	vppClient.cli = v.cli

	ch, err := v.handler.GetAPI()
	if err != nil {
		return err
	}
	vppClient.ch = ch

	vppClient.version, err = binapi.CompatibleVersion(ch)
	if err != nil {
		logrus.Warnf("binapi.CompatibleVersion error: %v", err)
	}

	info, err := v.GetVersionInfo()
	if err != nil {
		logrus.Warnf("GetVersionInfo error: %v", err)
	} else {
		logrus.WithField("instance", v.ID()).Debugf("version info: %+v", info)
	}

	for version := range binapi.Versions {
		ver := string(version)
		if len(ver) > 5 {
			ver = ver[:5]
		}
		logrus.Tracef("checking version %v in %q", ver, info.Version)
		if strings.Contains(info.Version, ver) {
			vppClient.version = version
			logrus.Debugf("found version %v in %q", ver, info.Version)
			break
		}
	}

	// register binapi messages to gob package (required for proxy)
	msgList, ok := binapi.Versions[vppClient.BinapiVersion()]
	if !ok {
		return fmt.Errorf("not found version %v", vppClient.BinapiVersion())
	}
	for _, msg := range msgList.AllMessages() {
		gob.Register(msg)
	}

	v.api = ch
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
