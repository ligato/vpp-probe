package agent

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/encoding/protojson"

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

// GetVppInterface returns VPP interface with name or nil if not found.
func (config *Config) GetVppInterface(name string) *VppInterface {
	for _, iface := range config.VPP.Interfaces {
		if iface.Value.Name == name {
			return &iface
		}
	}
	return nil
}

// GetLinuxInterface returns linux interface with name or nil if not found.
func (config *Config) GetLinuxInterface(name string) *LinuxInterface {
	for _, iface := range config.Linux.Interfaces {
		if iface.Value.Name == name {
			return &iface
		}
	}
	return nil
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
	Metadata map[string]interface{} `json:",omitempty"`
	Origin   ValueOrigin
}

type ValueOrigin api.ValueOrigin

func (v ValueOrigin) MarshalJSON() ([]byte, error) {
	return json.Marshal(api.ValueOrigin(v).String())
}

func (v *ValueOrigin) UnmarshalJSON(data []byte) error {
	var vo api.ValueOrigin
	err := json.Unmarshal(data, &vo)
	if err == nil {
		*v = ValueOrigin(vo)
		return nil
	}
	var origin string
	if err := json.Unmarshal(data, &origin); err != nil {
		return err
	}
	switch origin {
	case api.FromNB.String():
		*v = ValueOrigin(api.FromNB)
	case api.FromSB.String():
		*v = ValueOrigin(api.FromSB)
	default:
		*v = ValueOrigin(api.UnknownOrigin)
	}
	return nil
}

func RetrieveConfig(handler probe.Handler) (*Config, error) {
	return retrieveConfig(handler, false)
}

func retrieveConfig(handler probe.Handler, cached bool) (*Config, error) {
	var config Config

	// dump running config
	viewType := "SB"
	if cached {
		viewType = "cached"
	}
	if err := dumpConfig(handler, &config, viewType); err != nil {
		return nil, err
	}

	// sort interfaces by index
	sort.Slice(config.VPP.Interfaces, func(i, j int) bool {
		return config.VPP.Interfaces[i].Index() < config.VPP.Interfaces[j].Index()
	})

	// get status for values
	if err := getValues(handler, &config); err != nil {
		logrus.Errorf("getting value  failed: %v", err)
	}

	// retrieve additional metadata
	if err := retrieveMetadata(handler, &config); err != nil {
		logrus.Errorf("retrieving metadata failed: %v", err)
	}

	return &config, nil
}

func getValues(handler probe.Handler, c *Config) error {
	log := logrus.WithFields(map[string]interface{}{
		"instance": handler.ID(),
	})

	resp, err := runAgentctlCmd(handler, "values", "--format", "json")
	if err != nil {
		return fmt.Errorf("dumping all failed: %w", err)
	}
	log.Tracef("values response %d bytes", len(resp))

	var values []*kvscheduler.BaseValueStatus
	if err := json.Unmarshal(resp, &values); err != nil {
		logrus.Tracef("json data: %s", resp)
		return fmt.Errorf("unmarshaling status values failed: %w", err)
	}
	log.Debugf("retrieved %d values", len(values))

	// store interfaces to a map
	keys := map[string]int{}
	for i, iface := range c.VPP.Interfaces {
		keys[iface.Value.Name] = i
	}

	for _, value := range values {
		log.Tracef(" - %+v", value)

		// interface link state
		if ifaceName, isUp, ok := vpp_interfaces.ParseLinkStateKey(value.Value.Key); ok {
			if i, ok := keys[ifaceName]; ok {
				c.VPP.Interfaces[i].Metadata["linkstate"] = isUp
			} else {
				log.Tracef("link state for unknown interface %q", ifaceName)
			}
		}
	}

	return nil
}

func dumpConfig(handler probe.Handler, config *Config, viewType string) error {
	log := logrus.WithFields(map[string]interface{}{
		"instance": handler.ID(),
	})

	// execute agentctl dump
	dump, err := runAgentctlCmd(handler, "dump", "--format", `'{{printf "["}}{{range $i, $e := .}}{{if $i}}, {{end}}{{printf "{ \"Key\": \"%s\",\n" $e.Key}}{{printf "\"Value\": %s,\n" (json $e.Value)}}{{printf "\"Metadata\": %s,\n\"Origin\": \"%v\"\n}" (json $e.Metadata) ($e.Origin)}}{{end}}{{printf "]"}}'`, "--view", viewType, "all")
	if err != nil {
		return fmt.Errorf("executing dump failed: %w", err)
	}
	log.Tracef("dump response %d bytes", len(dump))

	var list []KVData
	if err := json.Unmarshal(dump, &list); err != nil {
		log.Tracef("dump json data: %s", dump)
		return fmt.Errorf("unmarshaling dump failed: %w", err)
	}
	if list == nil {
		return fmt.Errorf("unmarshaled dump is nil")
	}
	if len(list) == 0 {
		log.Tracef("dump data: %s", dump)
		return fmt.Errorf("no items in dump")
	}
	log.Debugf("dump contains %d items", len(list))

	var errs []error

	for i, item := range list {
		log.Tracef("- item #%d/%d (%s) %s", i, len(list), item.Key, item.Value)

		model, err := models.GetModelForKey(item.Key)
		if err != nil {
			err = errors.Wrapf(err, "failed to get model for key %v", item.Key)
			log.Warn(err)
			errs = append(errs, err)
			continue
		}

		switch model.Name() {
		case linux_interfaces.ModelInterface.Name():
			var value = LinuxInterface{KVData: item}
			value.Value = linux_interfaces.ModelInterface.NewInstance().(*linux_interfaces.Interface)
			if err := protojson.Unmarshal(item.Value, value.Value); err != nil {
				err = errors.Wrapf(err, "unmarshal value failed")
				log.Warn(err)
				errs = append(errs, err)
				continue
			}
			config.Linux.Interfaces = append(config.Linux.Interfaces, value)

		case linux_l3.ModelRoute.Name():
			var value = LinuxRoute{KVData: item}
			value.Value = linux_l3.ModelRoute.NewInstance().(*linux_l3.Route)
			if err := protojson.Unmarshal(item.Value, value.Value); err != nil {
				err = errors.Wrapf(err, "unmarshal value failed")
				log.Warn(err)
				errs = append(errs, err)
				continue
			}
			config.Linux.Routes = append(config.Linux.Routes, value)

		case vpp_interfaces.ModelInterface.Name():
			var value = VppInterface{KVData: item}
			value.Value = vpp_interfaces.ModelInterface.NewInstance().(*vpp_interfaces.Interface)
			if err := protojson.Unmarshal(item.Value, value.Value); err != nil {
				err = errors.Wrapf(err, "unmarshal value failed")
				log.Warn(err)
				errs = append(errs, err)
				continue
			}
			config.VPP.Interfaces = append(config.VPP.Interfaces, value)

		case vpp_l3.ModelRoute.Name():
			var value = VppRoute{KVData: item}
			value.Value = vpp_l3.ModelRoute.NewInstance().(*vpp_l3.Route)
			if err := protojson.Unmarshal(item.Value, value.Value); err != nil {
				err = errors.Wrapf(err, "unmarshal value failed")
				log.Warn(err)
				errs = append(errs, err)
				continue
			}
			config.VPP.Routes = append(config.VPP.Routes, value)

		case vpp_l2.ModelXConnectPair.Name():
			var value = VppL2XConnect{KVData: item}
			if err := json.Unmarshal(item.Value, &value.Value); err != nil {
				err = errors.Wrapf(err, "unmarshal value failed")
				log.Warn(err)
				errs = append(errs, err)
				continue
			}
			config.VPP.L2XConnects = append(config.VPP.L2XConnects, value)

		case vpp_ipsec.ModelTunnelProtection.Name():
			var value = VppIPSecTunProtect{KVData: item}
			if err := json.Unmarshal(item.Value, &value.Value); err != nil {
				err = errors.Wrapf(err, "unmarshal value failed")
				log.Warn(err)
				errs = append(errs, err)
				continue
			}
			config.VPP.IPSecTunProtects = append(config.VPP.IPSecTunProtects, value)

		case vpp_ipsec.ModelSecurityAssociation.Name():
			var value = VppIPSecSA{KVData: item}
			if err := json.Unmarshal(item.Value, &value.Value); err != nil {
				err = errors.Wrapf(err, "unmarshal value failed")
				log.Warn(err)
				errs = append(errs, err)
				continue
			}
			config.VPP.IPSecSAs = append(config.VPP.IPSecSAs, value)

		case vpp_ipsec.ModelSecurityPolicyDatabase.Name():
			var value = VppIPSecSPD{KVData: item}
			if err := json.Unmarshal(item.Value, &value.Value); err != nil {
				err = errors.Wrapf(err, "unmarshal value failed")
				log.Warn(err)
				errs = append(errs, err)
				continue
			}
			config.VPP.IPSecSPDs = append(config.VPP.IPSecSPDs, value)

		case vpp_ipsec.ModelSecurityPolicy.Name():
			var value = VppIPSecSP{KVData: item}
			if err := json.Unmarshal(item.Value, &value.Value); err != nil {
				err = errors.Wrapf(err, "unmarshal value failed")
				log.Warn(err)
				errs = append(errs, err)
				continue
			}
			config.VPP.IPSecSPs = append(config.VPP.IPSecSPs, value)

		default:
			err := errors.Errorf("unhandled model: %s, ignoring key %q", model.Name(), item.Key)
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		log.Warnf("processing dump finished with %d errors", len(errs))
	}

	return nil
}

func retrieveMetadata(handler probe.Handler, config *Config) error {
	log := logrus.WithFields(map[string]interface{}{
		"instance": handler.ID(),
	})

	// VPP interfaces metadata
	for i, iface := range config.VPP.Interfaces {

		// ensure metadata is initialized
		if iface.Metadata == nil {
			iface.Metadata = make(map[string]interface{})
		}

		// get interface-type specific data
		switch iface.Value.GetType() {

		case vpp_interfaces.Interface_MEMIF:
			log.WithFields(map[string]interface{}{
				"interface": iface.Value.Name,
				"instance":  handler.ID(),
			}).Tracef("getting metadata for memif interface: %v", iface.Value.Name)

			socketFile := iface.Value.GetMemif().GetSocketFilename()
			iface.Metadata["inode"] = getInodeForFile(handler, socketFile)

			config.VPP.Interfaces[i] = iface
		}
	}

	return nil
}

func HasVppInterfaceType(c *Config, typ vpp_interfaces.Interface_Type) bool {
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

func findIPSecSPsFor(spdIdx uint32, config *Config) []*VppIPSecSP {
	var sps []*VppIPSecSP
	for _, tp := range config.VPP.IPSecSPs {
		if spdIdx == tp.Value.SpdIndex {
			sps = append(sps, &tp)
		}
	}
	return sps
}

func FindIPSecSPFor(iface string, config *Config) []*VppIPSecSP {
	for _, tp := range config.VPP.IPSecSPDs {
		for _, ifc := range tp.Value.Interfaces {
			if iface == ifc.Name {
				return findIPSecSPsFor(tp.Value.Index, config)
			}
		}
	}
	return nil
}

func FindVppRoutesFor(iface string, routes []VppRoute) []VppRoute {
	var list []VppRoute
	for _, r := range routes {
		if api.ValueOrigin(r.Origin) == api.FromSB {
			continue
		}
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
