package agent

import (
	"encoding/json"
	"fmt"

	"github.com/sirupsen/logrus"
	"go.ligato.io/vpp-agent/v3/pkg/models"
	linux_interfaces "go.ligato.io/vpp-agent/v3/proto/ligato/linux/interfaces"
	vpp_interfaces "go.ligato.io/vpp-agent/v3/proto/ligato/vpp/interfaces"
	vpp_ipsec "go.ligato.io/vpp-agent/v3/proto/ligato/vpp/ipsec"
	vpp_l2 "go.ligato.io/vpp-agent/v3/proto/ligato/vpp/l2"

	"go.ligato.io/vpp-probe/probe"
)

type Config struct {
	VPP struct {
		Interfaces       []VppInterface
		L2XConnects      []VppL2XConnect      `json:",omitempty"`
		IPSecTunProtects []VppIPSecTunProtect `json:",omitempty"`
		IPSecSAs         []VppIPSecSA         `json:",omitempty"`
		IPSecSPDs        []VppIPSecSPD        `json:",omitempty"`
	}
	Linux struct {
		Interfaces []LinuxInterface
	}
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

func HasAnyIPSecConfig(config *Config) bool {
	if config == nil {
		return false
	}
	switch {
	case len(config.VPP.IPSecTunProtects) > 0,
		len(config.VPP.IPSecSAs) > 0:
		return true
	}
	return false
}

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

type VppIPSecSPD struct {
	KVData
	Value *vpp_ipsec.SecurityPolicyDatabase
}

func retrieveConfig(host probe.Handler) (*Config, error) {
	dump, err := runAgentctlCmd(host, "dump", "-f ", "json", "--view ", "SB", "all")
	if err != nil {
		return nil, fmt.Errorf("dumping all failed: %w", err)
	}
	logrus.Debugf("dump response %d bytes", len(dump))

	var list []KVData
	if err := json.Unmarshal(dump, &list); err != nil {
		logrus.Tracef("json data: %s", dump)
		return nil, fmt.Errorf("unmarshaling dump failed: %w", err)
	}
	logrus.Debugf("dumped %d items", len(list))

	var config Config
	for _, item := range list {
		model, err := models.GetModelForKey(item.Key)
		if err != nil {
			logrus.Tracef("GetModelForKey error: %v", err)
			continue
		}

		switch model.Name() {
		case vpp_interfaces.ModelInterface.Name():
			var value = VppInterface{KVData: item}
			if err := json.Unmarshal(item.Value, &value.Value); err != nil {
				logrus.Warnf("unmarshal value failed: %v", err)
				continue
			}
			config.VPP.Interfaces = append(config.VPP.Interfaces, value)

		case linux_interfaces.ModelInterface.Name():
			var value = LinuxInterface{KVData: item}
			if err := json.Unmarshal(item.Value, &value.Value); err != nil {
				logrus.Warnf("unmarshal value failed: %v", err)
				continue
			}
			config.Linux.Interfaces = append(config.Linux.Interfaces, value)

		case vpp_l2.ModelXConnectPair.Name():
			var value = VppL2XConnect{KVData: item}
			if err := json.Unmarshal(item.Value, &value.Value); err != nil {
				logrus.Warnf("unmarshal value failed: %v", err)
				continue
			}
			config.VPP.L2XConnects = append(config.VPP.L2XConnects, value)

		case vpp_ipsec.ModelTunnelProtection.Name():
			var value = VppIPSecTunProtect{KVData: item}
			if err := json.Unmarshal(item.Value, &value.Value); err != nil {
				logrus.Warnf("unmarshal value failed: %v", err)
				continue
			}
			config.VPP.IPSecTunProtects = append(config.VPP.IPSecTunProtects, value)

		case vpp_ipsec.ModelSecurityAssociation.Name():
			var value = VppIPSecSA{KVData: item}
			if err := json.Unmarshal(item.Value, &value.Value); err != nil {
				logrus.Warnf("unmarshal value failed: %v", err)
				continue
			}
			config.VPP.IPSecSAs = append(config.VPP.IPSecSAs, value)

		case vpp_ipsec.ModelSecurityPolicyDatabase.Name():
			var value = VppIPSecSPD{KVData: item}
			if err := json.Unmarshal(item.Value, &value.Value); err != nil {
				logrus.Warnf("unmarshal value failed: %v", err)
				continue
			}
			config.VPP.IPSecSPDs = append(config.VPP.IPSecSPDs, value)

		default:
			logrus.Debugf("ignoring value for key %q", item.Key)
		}
	}

	return &config, nil
}
