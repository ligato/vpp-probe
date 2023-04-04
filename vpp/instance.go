// Package vpp handles the VPP instance.
package vpp

import (
	"encoding/gob"
	"encoding/json"
	"fmt"
	"runtime/debug"
	"strings"

	"github.com/sirupsen/logrus"
	govppapi "go.fd.io/govpp/api"
	"go.ligato.io/vpp-agent/v3/plugins/vpp/binapi"

	"go.ligato.io/vpp-probe/pkg/exec"
	"go.ligato.io/vpp-probe/pkg/log"
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

	status        *APIStatus
	vppInfo       api.VppInfo
	vppStats      *api.VppStats
	vppInterfaces []*api.Interface
}

// NewInstance tries to initialize probe and returns a new Instance on success.
func NewInstance(probe probe.Handler) (*Instance, error) {
	h := &Instance{
		handler: probe,
		status:  &APIStatus{},
	}
	return h, nil
}

type instanceData struct {
	ID       string
	Metadata map[string]string
	Status   *APIStatus
	VppInfo  api.VppInfo
	VppStats *api.VppStats
	Agent    *agent.Instance
}

func (v *Instance) MarshalJSON() ([]byte, error) {
	instance := instanceData{
		ID:       v.handler.ID(),
		Metadata: v.handler.Metadata(),
		VppInfo:  v.vppInfo,
		Agent:    v.agent,
		Status:   v.status,
		VppStats: v.vppStats,
	}
	return json.Marshal(instance)
}

func (v *Instance) UnmarshalJSON(data []byte) error {
	var instance instanceData
	if err := json.Unmarshal(data, &instance); err != nil {
		return err
	}
	v.handler = &dummyHandler{
		id:       instance.ID,
		metadata: instance.Metadata,
	}
	v.vppInfo = instance.VppInfo
	v.agent = instance.Agent
	v.status = instance.Status
	return nil
}

func (v Instance) String() string {
	return v.handler.Metadata()["name"]
}

func (v *Instance) ID() string {
	return fmt.Sprintf("instance::%s", v.handler.ID())
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

func (v *Instance) VppInfo() api.VppInfo {
	return v.vppInfo
}

func (v *Instance) VppStats() *api.VppStats {
	return v.vppStats
}

func (v *Instance) VppInterfaces() []*api.Interface {
	return v.vppInterfaces
}

func (v *Instance) Init() (err error) {
	l := logrus.WithFields(map[string]interface{}{
		"instance": v.ID(),
	})

	defer log.TraceElapsed(l, "init vpp instance")()

	if err = v.initVPP(); err != nil {
		v.status.LastErr = err
		return err
	}

	if err = v.initAgent(); err != nil {
		l.Debugf("vpp agent not detected")
	}

	var vppInfo api.VppInfo

	buildInfo, err := v.GetBuildInfo()
	if err != nil {
		v.status.LastErr = err
		return err
	}
	vppInfo.Build = *buildInfo

	if sysInfo, err := v.GetSystemInfo(); err != nil {
		l.Debugf("getting system info failed: %v", err)
	} else {
		vppInfo.Runtime = *sysInfo
	}

	v.vppInfo = vppInfo

	if stats, err := v.DumpStats(); err != nil {
		l.Debugf("dumping VPP stats failed: %v", err)
	} else {
		v.vppStats = stats
	}

	if interfaces, err := v.ListInterfaces(); err != nil {
		l.Debugf("dumping VPP interfaces failed: %v", err)
	} else {
		v.vppInterfaces = interfaces
	}

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
	vppctl := "/usr/bin/vppctl"
	if _, err := v.handler.Command("ls", vppctl).Output(); err != nil {
		vppctl = "vppctl"
	}
	wrapper := exec.Wrap(v.handler, vppctl, args...)
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

	version, err := v.GetVersion()
	if err != nil {
		logrus.Warnf("GetVersionInfo error: %v", err)
	} else {
		logrus.WithField("instance", v.ID()).Debugf("version: %q", version)

		for v := range binapi.Versions {
			ver := string(v)
			if len(ver) > 5 {
				ver = ver[:5]
			}
			logrus.Tracef("checking version %v in %q", ver, version)
			if strings.Contains(version, ver) {
				vppClient.version = v
				logrus.Debugf("found version %v in %q", ver, version)
				break
			}
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
