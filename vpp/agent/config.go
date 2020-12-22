package agent

import (
	"strings"

	"go.ligato.io/vpp-agent/v3/plugins/kvscheduler/api"
	linux_interfaces "go.ligato.io/vpp-agent/v3/proto/ligato/linux/interfaces"
	vpp_interfaces "go.ligato.io/vpp-agent/v3/proto/ligato/vpp/interfaces"
	vpp_ipsec "go.ligato.io/vpp-agent/v3/proto/ligato/vpp/ipsec"
	vpp_l2 "go.ligato.io/vpp-agent/v3/proto/ligato/vpp/l2"

	"go.ligato.io/vpp-probe/probe"
)

const defaultVppInterfaceLocal0 = "local0"

type LinuxInterface struct {
	KVData
	Value *linux_interfaces.Interface
}

type VppInterface struct {
	KVData
	Value *vpp_interfaces.Interface
}

type VppL2XConnect struct {
	KVData
	Value *vpp_l2.XConnectPair
}

type VppIPSecTunProtect struct {
	KVData
	Value *vpp_ipsec.TunnelProtection
}

type VppIPSecSA struct {
	KVData
	Value *vpp_ipsec.SecurityAssociation
}

func retrieveInterfacesVpp(handler probe.Host) ([]VppInterface, error) {
	var list []VppInterface
	err := listModelData(handler, vpp_interfaces.ModelInterface, &list)
	if err != nil {
		return nil, err
	}

	var ifaces []VppInterface
	for _, iface := range list {
		if iface.Origin == api.FromSB && strings.HasSuffix(iface.Value.Name, defaultVppInterfaceLocal0) {
			continue
		}
		ifaces = append(ifaces, iface)
	}
	return ifaces, nil
}

func retrieveInterfacesLinux(handler probe.Host) ([]LinuxInterface, error) {
	var list []LinuxInterface
	err := listModelData(handler, linux_interfaces.ModelInterface, &list)
	if err != nil {
		return nil, err
	}

	var ifaces []LinuxInterface
	for _, iface := range list {
		if iface.Origin == api.FromSB {
			continue
		}
		ifaces = append(ifaces, iface)
	}

	return ifaces, nil
}

func retrieveL2XConnects(handler probe.Host) ([]VppL2XConnect, error) {
	var list []VppL2XConnect
	err := listModelData(handler, vpp_l2.ModelXConnectPair, &list)
	if err != nil {
		return nil, err
	}

	return list, nil
}

func retrieveIPSecTunProtects(handler probe.Host) ([]VppIPSecTunProtect, error) {
	var list []VppIPSecTunProtect

	err := listModelData(handler, vpp_ipsec.ModelTunnelProtection, &list)
	if err != nil {
		return nil, err
	}

	return list, nil
}

func retrieveIPSecSAs(handler probe.Host) ([]VppIPSecSA, error) {
	var list []VppIPSecSA
	err := listModelData(handler, vpp_ipsec.ModelSecurityAssociation, &list)
	if err != nil {
		return nil, err
	}

	return list, nil
}
