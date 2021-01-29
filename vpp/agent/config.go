package agent

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"

	"github.com/sirupsen/logrus"
	"go.ligato.io/vpp-agent/v3/pkg/models"
	"go.ligato.io/vpp-agent/v3/plugins/kvscheduler/api"
	linux_interfaces "go.ligato.io/vpp-agent/v3/proto/ligato/linux/interfaces"
	linux_l3 "go.ligato.io/vpp-agent/v3/proto/ligato/linux/l3"
	vpp_interfaces "go.ligato.io/vpp-agent/v3/proto/ligato/vpp/interfaces"
	vpp_ipsec "go.ligato.io/vpp-agent/v3/proto/ligato/vpp/ipsec"
	vpp_l2 "go.ligato.io/vpp-agent/v3/proto/ligato/vpp/l2"
	vpp_l3 "go.ligato.io/vpp-agent/v3/proto/ligato/vpp/l3"

	"go.ligato.io/vpp-probe/probe"
)

type Config struct {
	VPP struct {
		Interfaces       []VppInterface
		Routes           []VppRoute           `json:",omitempty"`
		L2XConnects      []VppL2XConnect      `json:",omitempty"`
		IPSecTunProtects []VppIPSecTunProtect `json:",omitempty"`
		IPSecSAs         []VppIPSecSA         `json:",omitempty"`
		IPSecSPDs        []VppIPSecSPD        `json:",omitempty"`
	}
	Linux struct {
		Interfaces []LinuxInterface
		Routes     []LinuxRoute `json:",omitempty"`
	}
}

type LinuxInterface struct {
	KVData
	Value *linux_interfaces.Interface
}

func (v *LinuxInterface) Index() int {
	return toInt(v.Metadata["LinuxIfIndex"])
}

type LinuxRoute struct {
	KVData
	Value *linux_l3.Route
}

type VppInterface struct {
	KVData
	Value *vpp_interfaces.Interface
}

func (v *VppInterface) Index() int {
	return toInt(v.Metadata["SwIfIndex"])
}

type VppRoute struct {
	KVData
	Value *vpp_l3.Route
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

type KVData struct {
	Key      string
	Value    json.RawMessage
	Metadata map[string]interface{}
	Origin   api.ValueOrigin
}

func RetrieveConfig(handler probe.Handler) (*Config, error) {
	dump, err := runAgentctlCmd(handler, "dump", "--format", "json", "--view ", "SB", "all")
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
		case linux_interfaces.ModelInterface.Name():
			var value = LinuxInterface{KVData: item}
			if err := json.Unmarshal(item.Value, &value.Value); err != nil {
				logrus.Warnf("unmarshal value failed: %v", err)
				continue
			}
			config.Linux.Interfaces = append(config.Linux.Interfaces, value)

		case linux_l3.ModelRoute.Name():
			var value = LinuxRoute{KVData: item}
			if err := json.Unmarshal(item.Value, &value.Value); err != nil {
				logrus.Warnf("unmarshal value failed: %v", err)
				continue
			}
			config.Linux.Routes = append(config.Linux.Routes, value)

		case vpp_interfaces.ModelInterface.Name():
			var value = VppInterface{KVData: item}
			if err := json.Unmarshal(item.Value, &value.Value); err != nil {
				logrus.Warnf("unmarshal value failed: %v", err)
				continue
			}
			config.VPP.Interfaces = append(config.VPP.Interfaces, value)

		case vpp_l3.ModelRoute.Name():
			var value = VppRoute{KVData: item}
			if err := json.Unmarshal(item.Value, &value.Value); err != nil {
				logrus.Warnf("unmarshal value failed: %v", err)
				continue
			}
			config.VPP.Routes = append(config.VPP.Routes, value)

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

	// Sort interfaces by index
	sort.Slice(config.VPP.Interfaces, func(i, j int) bool {
		return config.VPP.Interfaces[i].Index() < config.VPP.Interfaces[j].Index()
	})

	return &config, nil
}

func (c *Config) HasVppInterfaceType(typ vpp_interfaces.Interface_Type) bool {
	for _, iface := range c.VPP.Interfaces {
		if iface.Value.Type == typ {
			return true
		}
	}
	return false
}

func FindL2XconnFor(iface string, l2XConnects []VppL2XConnect) *VppL2XConnect {
	for _, xconn := range l2XConnects {
		if iface == xconn.Value.ReceiveInterface ||
			iface == xconn.Value.TransmitInterface {
			return &xconn
		}
	}
	return nil
}

func FindIPSecTunProtectFor(iface string, tunProtects []VppIPSecTunProtect) *VppIPSecTunProtect {
	for _, tp := range tunProtects {
		if iface == tp.Value.Interface {
			return &tp
		}
	}
	return nil
}

func FindVppRoutesFor(iface string, routes []VppRoute) []VppRoute {
	var list []VppRoute
	for _, r := range routes {
		if iface == r.Value.OutgoingInterface {
			list = append(list, r)
		}
	}
	return list
}

func HasAnyIPSecConfig(config *Config) bool {
	if config == nil {
		return false
	}
	switch {
	case len(config.VPP.IPSecTunProtects) > 0,
		len(config.VPP.IPSecSAs) > 0,
		len(config.VPP.IPSecSPDs) > 0:
		return true
	}
	return false
}

func toInt(v interface{}) int {
	s := fmt.Sprint(v)
	idx, _ := strconv.Atoi(s)
	return idx
}
