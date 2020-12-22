package agent

import (
	"encoding/json"
	"strings"

	"github.com/sirupsen/logrus"
	vpp_interfaces "go.ligato.io/vpp-agent/v3/proto/ligato/vpp/interfaces"

	"go.ligato.io/vpp-probe/probe"
)

type ExtraCLIs map[string]string

func (e ExtraCLIs) MarshalJSON() ([]byte, error) {
	clis := map[string][]string{}
	for k, v := range e {
		clis[k] = strings.Split(v, "\n")
	}
	return json.Marshal(clis)
}

type Instance struct {
	*probe.Instance `json:"Instance"`
	cli             probe.CliExecutor

	Version string
	Extra   ExtraCLIs `json:",omitempty"`

	// Interfaces
	VppInterfaces   []VppInterface
	LinuxInterfaces []LinuxInterface `json:",omitempty"`

	// L2XConn
	L2XConnects []VppL2XConnect `json:",omitempty"`

	// IPSec
	IPSecTunProtects []VppIPSecTunProtect `json:",omitempty"`
	IPSecSAs         []VppIPSecSA         `json:",omitempty"`
}

func NewInstance(handler *probe.Instance) (*Instance, error) {
	cli, err := handler.GetCLI()
	if err != nil {
		return nil, err
	}
	instance := &Instance{
		Instance: handler,
		Extra:    map[string]string{},
		cli:      cli,
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
	vpp.Extra[cmd] = out
	return out, nil
}

func UpdateInstanceInfo(instance *Instance) (err error) {
	instance.VppInterfaces, err = retrieveInterfacesVpp(instance.Handler)
	if err != nil {
		logrus.Warnf("dump vpp interfaces failed: %v", err)
	}

	instance.LinuxInterfaces, err = retrieveInterfacesLinux(instance.Handler)
	if err != nil {
		logrus.Warnf("dump linux interfaces failed: %v", err)
	}

	instance.L2XConnects, err = retrieveL2XConnects(instance.Handler)
	if err != nil {
		logrus.Warnf("dump l2xconnect failed %v", err)
	}

	instance.IPSecTunProtects, err = retrieveIPSecTunProtects(instance.Handler)
	if err != nil {
		logrus.Warnf("dump ipsec tun protects failed: %v", err)
	}

	instance.IPSecSAs, err = retrieveIPSecSAs(instance.Handler)
	if err != nil {
		logrus.Warnf("dump ipsec SAs failed: %v", err)
	}

	return nil
}

func ListVppInterfacesType(typ vpp_interfaces.Interface_Type, ifaces []VppInterface) []VppInterface {
	var list []VppInterface
	for _, iface := range ifaces {
		if iface.Value.Type == typ {
			list = append(list, iface)
		}
	}
	return list
}

func HasVppInterfaceType(typ vpp_interfaces.Interface_Type, ifaces []VppInterface) bool {
	for _, iface := range ifaces {
		if iface.Value.Type == typ {
			return true
		}
	}
	return false
}

func FindL2XconnFor(intfName string, l2XConnects []VppL2XConnect) *VppL2XConnect {
	for _, xconn := range l2XConnects {
		if intfName == xconn.Value.ReceiveInterface ||
			intfName == xconn.Value.TransmitInterface {
			return &xconn
		}
	}
	return nil
}

func FindIPSecTunProtectFor(intfName string, tunProtects []VppIPSecTunProtect) *VppIPSecTunProtect {
	for _, tp := range tunProtects {
		if intfName == tp.Value.Interface {
			return &tp
		}
	}
	return nil
}

func HasAnyIPSecConfig(vpp *Instance) bool {
	switch {
	case len(vpp.IPSecTunProtects) > 0,
		len(vpp.IPSecSAs) > 0:
		return true
	}
	return false
}

var DefaultCLIs = []string{
	"show interface",
	"show mode",
	"show hardware detail",
	"show ip fib",
	"show ip neighbor",
	"show err",
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

	if HasVppInterfaceType(vpp_interfaces.Interface_MEMIF, vpp.VppInterfaces) {
		runCli("show memif")
	}
	if HasVppInterfaceType(vpp_interfaces.Interface_VXLAN_TUNNEL, vpp.VppInterfaces) {
		runCli("show vxlan tunnel")
	}
	if HasVppInterfaceType(vpp_interfaces.Interface_TAP, vpp.VppInterfaces) {
		runCli("show tap")
	}
	if HasVppInterfaceType(vpp_interfaces.Interface_IPIP_TUNNEL, vpp.VppInterfaces) {
		runCli("show ipip tunnel")
	}
	if HasAnyIPSecConfig(vpp) {
		runCli("show ipsec all")
	}

	for _, cli := range extra {
		runCli(cli)
	}
}
