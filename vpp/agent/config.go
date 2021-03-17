package agent

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/sirupsen/logrus"
	"go.ligato.io/vpp-agent/v3/pkg/models"
	"go.ligato.io/vpp-agent/v3/plugins/kvscheduler/api"
	"go.ligato.io/vpp-agent/v3/proto/ligato/kvscheduler"
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
		IPSecSPs         []VppIPSecSP         `json:",omitempty"`
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

func (v *VppInterface) GetLinkState() bool {
	return toBool(v.Metadata["linkstate"])
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

type VppIPSecSP struct {
	KVData
	Value *vpp_ipsec.SecurityPolicy
}

type KVData struct {
	Key      string
	Value    json.RawMessage
	Metadata map[string]interface{}
	Origin   ValueOrigin
}

type ValueOrigin api.ValueOrigin

func (v ValueOrigin) MarshalJSON() ([]byte, error) {
	return json.Marshal(api.ValueOrigin(v).String())
}

func RetrieveConfig(handler probe.Handler) (*Config, error) {
	return retrieveConfigView(handler, false)
}

func retrieveConfigView(handler probe.Handler, cached bool) (*Config, error) {
	viewType := "SB"
	if cached {
		viewType = "cached"
	}

	var config Config

	if err := dumpConfig(handler, &config, viewType); err != nil {
		return nil, err
	}

	if err := getValues(handler, &config); err != nil {
		return nil, err
	}

	return &config, nil
}

func getValues(handler probe.Handler, c *Config) error {
	resp, err := runAgentctlCmd(handler, "values", "--format", "json")
	if err != nil {
		return fmt.Errorf("dumping all failed: %w", err)
	}
	logrus.Debugf("response %d bytes", len(resp))

	var values []*kvscheduler.BaseValueStatus
	if err := json.Unmarshal(resp, &values); err != nil {
		logrus.Tracef("json data: %s", resp)
		return fmt.Errorf("unmarshaling failed: %w", err)
	}
	logrus.Debugf("retrieved %d vales", len(values))

	keys := map[string]int{}
	for i, iface := range c.VPP.Interfaces {
		keys[iface.Value.Name] = i
	}

	for _, value := range values {
		logrus.Tracef(" - %+v", value)
		ifaceName, isUp, ok := vpp_interfaces.ParseLinkStateKey(value.Value.Key)
		if !ok {
			continue
		}
		if i, ok := keys[ifaceName]; ok {
			c.VPP.Interfaces[i].Metadata["linkstate"] = isUp
		} else {
			logrus.Debugf("link state for unknown interface %q", ifaceName)
		}
	}

	return nil
}

func dumpConfig(handler probe.Handler, config *Config, viewType string) error {
	dump, err := runAgentctlCmd(handler, "dump", "--format", "json", "--view", viewType, "all")
	if err != nil {
		return fmt.Errorf("dumping all failed: %w", err)
	}
	logrus.Debugf("response %d bytes", len(dump))

	var list []KVData
	if err := json.Unmarshal(dump, &list); err != nil {
		logrus.Tracef("json data: %s", dump)
		return fmt.Errorf("unmarshaling failed: %w", err)
	}
	logrus.Debugf("dumped %d items", len(list))

	for _, item := range list {
		logrus.Tracef(" - %+v", item)
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

		case vpp_ipsec.ModelSecurityPolicy.Name():
			var value = VppIPSecSP{KVData: item}
			if err := json.Unmarshal(item.Value, &value.Value); err != nil {
				logrus.Warnf("unmarshal value failed: %v", err)
				continue
			}
			config.VPP.IPSecSPs = append(config.VPP.IPSecSPs, value)

		default:
			logrus.Debugf("ignoring value for key %q", item.Key)
		}
	}

	// Sort interfaces by index
	sort.Slice(config.VPP.Interfaces, func(i, j int) bool {
		return config.VPP.Interfaces[i].Index() < config.VPP.Interfaces[j].Index()
	})

	return nil
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
		len(config.VPP.IPSecSPDs) > 0,
		len(config.VPP.IPSecSPs) > 0:
		return true
	}
	return false
}

func FindIPSecSA(saIdx uint32, ipsecSas []VppIPSecSA) *VppIPSecSA {
	for _, sa := range ipsecSas {
		if saIdx == sa.Value.Index {
			return &sa
		}
	}
	return nil
}
