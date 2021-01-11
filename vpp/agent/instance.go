package agent

import (
	"encoding/json"
	"strings"

	"github.com/sirupsen/logrus"
	vpp_interfaces "go.ligato.io/vpp-agent/v3/proto/ligato/vpp/interfaces"

	"go.ligato.io/vpp-probe/probe"
)

type Instance struct {
	probe.Handler `json:"Handler"`

	cli probe.CliExecutor

	Config  *Config
	Version string
	CliData CLIData `json:",omitempty"`
}

func NewInstance(handler probe.Handler) (*Instance, error) {
	cli, err := handler.GetCLI()
	if err != nil {
		return nil, err
	}
	instance := &Instance{
		Handler: handler,
		CliData: map[string]string{},
		cli:     cli,
	}
	if err := UpdateInstanceInfo(instance); err != nil {
		return nil, err
	}
	return instance, nil
}

func (vpp *Instance) RunCli(cmd string) (string, error) {
	out, err := vpp.cli.RunCli(cmd)
	if err != nil {
		return "", err
	}
	out = strings.ReplaceAll(out, "\r\r\n", "\n")
	out = strings.ReplaceAll(out, "\r\n", "\n")
	vpp.CliData[cmd] = out
	return out, nil
}

func UpdateInstanceInfo(instance *Instance) (err error) {
	instance.Config, err = retrieveConfig(instance.Handler)
	if err != nil {
		return err
	}
	return nil
}

var DefaultCLIs = []string{
	"show interface",
	"show mode",
	"show hardware detail",
	"show ip fib",
	"show ip neighbor",
	"show err",
}

type CLIData map[string]string

func (e CLIData) MarshalJSON() ([]byte, error) {
	clis := map[string][]string{}
	for k, v := range e {
		clis[k] = strings.Split(v, "\n")
	}
	return json.Marshal(clis)
}

func RunCLIs(vpp *Instance, extra []string) {
	runCli := func(cmd string) {
		_, err := vpp.RunCli(cmd)
		if err != nil {
			logrus.Errorf("cli %q error: %v", cmd, err)
		}
	}

	for _, cli := range DefaultCLIs {
		runCli(cli)
	}

	if HasVppInterfaceType(vpp_interfaces.Interface_MEMIF, vpp.Config.VPP.Interfaces) {
		runCli("show memif")
	}
	if HasVppInterfaceType(vpp_interfaces.Interface_VXLAN_TUNNEL, vpp.Config.VPP.Interfaces) {
		runCli("show vxlan tunnel")
	}
	if HasVppInterfaceType(vpp_interfaces.Interface_TAP, vpp.Config.VPP.Interfaces) {
		runCli("show tap")
	}
	if HasVppInterfaceType(vpp_interfaces.Interface_IPIP_TUNNEL, vpp.Config.VPP.Interfaces) {
		runCli("show ipip tunnel")
	}
	if HasAnyIPSecConfig(vpp.Config) {
		runCli("show ipsec all")
	}

	for _, cli := range extra {
		runCli(cli)
	}
}
