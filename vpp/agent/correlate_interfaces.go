package agent

import (
	"fmt"
	"github.com/sirupsen/logrus"
	vpp_interfaces "go.ligato.io/vpp-agent/v3/proto/ligato/vpp/interfaces"
	"go.ligato.io/vpp-probe/providers"
	"google.golang.org/protobuf/reflect/protoreflect"
	"sort"
	"strings"
)

type ForwarderConnectionType int
const (
	TapHead ForwarderConnectionType = iota
	MemifHead
	VxlanHead
)

type ForwarderIfContextType int
const (
	ForwarderContextVPP ForwarderIfContextType = iota
	ForwarderContextLinux
)
type NormalizedIfType int
const (
	UNKNOWN NormalizedIfType = iota
	TAP
	MEMIF
	VXLAN
	AF_PACKET
)
func (n NormalizedIfType) String() string {
	return [...]string{"UNKNOWN",
		"TAP", "MEMIF", "VXLAN", "AF_PACKET"}[n]
}

type IfOwner struct {
	Cluster string
	Node string
	Pod string
}

type ForwarderIfNormalizedConfig interface {
	IsEqual(ForwarderIfNormalizedConfig) bool
	MatchKey() string  // key that matches peer interfaces (built from intf properties)
	ToString() string
}

type ForwarderIf struct {
	Owner IfOwner
	IfContextType ForwarderIfContextType
	IfName string
	InternalIfName string
	NormalizedType NormalizedIfType
	NormalizedConfig ForwarderIfNormalizedConfig // socket:tag, vxlan:src/dest VNI, tap name
	CorrelatedConnection *ForwarderConnection
}

type ForwarderConnection struct {
	Type ForwarderConnectionType
	IntfPath []*ForwarderIf
}

/*
   nodes -> pods = instances
   vxlan intf -> src,dst,vni
     src IP = local nodes' IP
     dst IP = external IP of peer node (it's in addresses list for host_network VPP instances)

*/
type ForwarderConnCorrelations struct {
	instances []*Instance
	VppInstance map[string]map[string]*Instance // map[nodeName][podName] = VPP instance
	Ip2Vpp map[string]*Instance //map[IP address] = vpp-forwarder
	AfPacketIf2Instance map[string]*Instance // map[af_packetIntf IP] = VPP Instance
	Connections []*ForwarderConnection
	AllIfs []*ForwarderIf
	PodIfs map[string]map[string]*ForwarderIf // map[pod][ifName] = intf
	IfInterconnects map[NormalizedIfType]map[string][]*ForwarderIf // pairs of interconnect intfs map[type][IfMatchkey]{ forwarderIf1, forwarderIf2 }
	IfXconnects map[string]map[string]string // map[pod][ifName] = xconn peer ifName
}

type MemifNormalizedConfig struct {
	socketFile string
	id string
	isMaster bool
}
func (m MemifNormalizedConfig) IsEqual(normIf ForwarderIfNormalizedConfig) bool {
	m2, ok := normIf.(MemifNormalizedConfig)
	if !ok {
		return false
	}
	if m.socketFile == m2.socketFile {
		return true
	}
	return false
}
func (m MemifNormalizedConfig) ToString() string {
	if (m.isMaster) {
		fmt.Sprintf("%s (master)", m.socketFile)
	}
	return fmt.Sprintf("%s", m.socketFile)
}
func (m MemifNormalizedConfig) MatchKey() string {
	dirComps := strings.Split(m.socketFile, "/")
	return fmt.Sprintf("%s", strings.Join(dirComps[len(dirComps)-2:], "/"))
}

type VxlanNormalizedConfig struct {
	src string
	dst string
	vni uint32
	srcNodeAddresses []string // all node IP addresses mapping to src
	dstNodeAddresses []string // all node IP addresses mapping to dst
}
func NewVxlanNormalizedConfig(iface VppInterface, ip2VppInstance map[string]*Instance) (*VxlanNormalizedConfig) {
	vxlan := iface.Value.GetVxlan()

	srcInst, ok := ip2VppInstance[vxlan.SrcAddress]
	var srcAddresses []string
	if ok {
		srcAddresses = VppInstanceToAddresses(srcInst)
	} else {
		srcAddresses = []string{ vxlan.SrcAddress }
	}
	sort.Strings(srcAddresses)

	dstInst, ok := ip2VppInstance[vxlan.DstAddress]
	var dstAddresses []string
	if ok {
		dstAddresses = VppInstanceToAddresses(dstInst)
	} else {
		dstAddresses = []string{ vxlan.DstAddress }
	}
	sort.Strings(dstAddresses)
	return &VxlanNormalizedConfig {
		src: vxlan.SrcAddress,
		dst: vxlan.DstAddress,
		vni: vxlan.Vni,
		srcNodeAddresses: srcAddresses,
		dstNodeAddresses: dstAddresses,
	}
}
func (v VxlanNormalizedConfig) IsEqual(normIf ForwarderIfNormalizedConfig) bool {
	v2, ok := normIf.(VxlanNormalizedConfig)
	if !ok {
		return false
	}
	if ((v.src == v2.src && v.dst == v2.dst) ||
		(v.src == v2.dst && v.dst == v2.src)) &&
		v.vni == v2.vni {
		return true
	}
	return false
}
func (v VxlanNormalizedConfig) ToString() string {
	return fmt.Sprintf("%s <-> %s (%s)", v.src, v.dst, v.vni)
}
func (v VxlanNormalizedConfig) MatchKey() string {
	// Normalize for match key
	// make the tuple the lexigraphical order of the 1st pair of addresses
	srcAddr := v.srcNodeAddresses[0]
	dstAddr := v.dstNodeAddresses[0]
	if srcAddr > dstAddr {
		srcAddr = dstAddr
		dstAddr = v.srcNodeAddresses[0]
	}
	return fmt.Sprintf("%s,%s/%s", srcAddr, dstAddr, v.vni)
}

type TapNormalizedConfig struct {
	Name string
}
func (t TapNormalizedConfig) IsEqual(normIf ForwarderIfNormalizedConfig) bool {
	t2, ok := normIf.(TapNormalizedConfig)
	if !ok {
		return false
	}
	if t.Name == t2.Name {
		return true
	}
	return false
}
func (t TapNormalizedConfig) ToString() string {
	return fmt.Sprintf("%s", t.Name)
}
func (t TapNormalizedConfig) MatchKey() string {
	return fmt.Sprintf("%s", t.Name)
}

func protoFieldsToMap(fields protoreflect.FieldDescriptors, pb protoreflect.Message) map[string]string {
	m := map[string]string{}
	for i := 0; i < fields.Len(); i++ {
		fd := fields.Get(i)
		if pb.Has(fd) {
			f := pb.Get(fd)
			if f.IsValid() {
				m[string(fd.Name())] = f.String()
			}
		}
	}
	return m
}
func linuxIfToConfig(iface LinuxInterface) TapNormalizedConfig {
	ref := iface.Value.ProtoReflect()
	ld := ref.Descriptor().Oneofs().ByName("link")
	wd := ref.WhichOneof(ld)
	if wd == nil {
		return TapNormalizedConfig {Name: fmt.Sprintf("Errored-convert-%s", iface.Value.Name)}
	}
	d := wd.Message()
	link := ref.Get(wd).Message()
	m := protoFieldsToMap(d.Fields(), link)
	return TapNormalizedConfig {Name: m["vpp_tap_if_name"]}
}


func interfaceInternalName(iface VppInterface) string {
	if name, ok := iface.Metadata["InternalName"]; ok && name != nil {
		return fmt.Sprint(name)
	}
	return ""
}

func mapKeyValString(m map[string]string, f func(k string, v string) string) string {
	ss := make([]string, 0, len(m))
	for k, v := range m {
		s := f(k, v)
		if s == "" {
			continue
		}
		ss = append(ss, s)
	}
	return strings.Join(ss, " ")
}

func VppInstanceToAddresses(instance *Instance) []string {
	metadata := instance.handler.Metadata()
	return strings.Split(metadata["hostnet_addresses"], ",")
}

func newForwarderConnCorrelations(instances []*Instance) (*ForwarderConnCorrelations, error) {
	data := &ForwarderConnCorrelations{
		instances: instances,
		VppInstance: map[string]map[string]*Instance{}, // map[nodeName][podName] = VPP instance
		Ip2Vpp: map[string]*Instance{}, // map[node IP Address] = vpp instance (hostnetwork vpp)
		AfPacketIf2Instance: map[string]*Instance{}, // map[af_packetIntf IP] = VPP Instance
		Connections: []*ForwarderConnection{},
		AllIfs: []*ForwarderIf{},
		PodIfs: map[string]map[string]*ForwarderIf{},
		IfInterconnects: map[NormalizedIfType]map[string][]*ForwarderIf{},
		IfXconnects: map[string]map[string]string{},
	}

	for _, instance := range instances {
		metadata := instance.handler.Metadata()
		if metadata["env"] != providers.Kube {
			return nil, fmt.Errorf("NSM forwarder correlations only supported in K8s envs")
		}
		node := metadata["node"]
		if _, ok := data.VppInstance[node]; !ok {
			data.VppInstance[node] = make(map[string]*Instance)
		}
		podname := metadata["pod"]
		data.VppInstance[node][podname] = instance

		// Map node Addresses to hostnetwork vpp instances (e.g. nsm-forwarder)
		for _, address := range VppInstanceToAddresses(instance) {
			if address != "" {
				data.Ip2Vpp[address] = instance
			}
		}
	}
	return data, nil
}

func (c *ForwarderConnCorrelations) LinuxIfToInfo(cluster, node, pod string, linuxIf LinuxInterface) *ForwarderIf {
	iface := linuxIf.Value
	return &ForwarderIf {
		Owner: IfOwner{
			Cluster: cluster,
			Node:    node,
			Pod:     pod,
		},
		IfContextType: ForwarderContextLinux,
		IfName: iface.Name,
		InternalIfName: iface.HostIfName,
		NormalizedType: TAP,
		NormalizedConfig: linuxIfToConfig(linuxIf),
	}
}
func (c *ForwarderConnCorrelations) vppInterfaceInfo(iface VppInterface) (NormalizedIfType, ForwarderIfNormalizedConfig) {
	switch iface.Value.Type {
	case vpp_interfaces.Interface_MEMIF:
		memif := iface.Value.GetMemif()
		return MEMIF, MemifNormalizedConfig{ socketFile: memif.GetSocketFilename(), isMaster: memif.Master }

	case vpp_interfaces.Interface_VXLAN_TUNNEL:
		//vxlan := iface.Value.GetVxlan()
		//var info string
		//info += fmt.Sprintf("%s %s %s (vni:%v)", colorize(ipAddressColor, vxlan.SrcAddress), tunnelDirectionChar, colorize(ipAddressColor, vxlan.DstAddress), colorize(valueColor, vxlan.Vni))
		return VXLAN, NewVxlanNormalizedConfig(iface, c.Ip2Vpp)

	case vpp_interfaces.Interface_TAP:
		//tap := iface.Value.GetTap()
		//pr := tap.ProtoReflect()
		//m := protoFieldsToMap(pr.Descriptor().Fields(), pr)
		/*
			fieldsStr := mapKeyValString(m, func(k string, v string) string {
				return fmt.Sprintf("%s:%s", k, colorize(valueColor, v))
			})
			return fmt.Sprintf("host_if_name:%s %v", colorize(valueColor, iface.Metadata["TAPHostIfName"]), fieldsStr)
		*/
		// For comparison with the LinuxConfig we use the interface name
		return TAP, TapNormalizedConfig{Name: iface.Value.Name}
		//return TAP, TapNormalizedConfig{Name: fmt.Sprint(iface.Metadata["TAPHostIfName"])}

	case vpp_interfaces.Interface_IPIP_TUNNEL:
		tun := iface.Value.GetIpip()
		var info string
		info += fmt.Sprintf("%s %s mode:%v", tun.SrcAddr, tun.DstAddr, tun.TunnelMode)
		return UNKNOWN, TapNormalizedConfig{Name: info}

	}

	ref := iface.Value.ProtoReflect()
	ld := ref.Descriptor().Oneofs().ByName("link")
	wd := ref.WhichOneof(ld)
	if wd == nil {
		return UNKNOWN, TapNormalizedConfig{Name: fmt.Sprintf("Errored-convert-%s", iface.Value.Name)}
	}
	d := wd.Message()
	link := ref.Get(wd).Message()

	m := protoFieldsToMap(d.Fields(), link)
	info := mapKeyValString(m, func(k string, v string) string {
		return fmt.Sprintf("%s:%s", k, v)
	})
	return UNKNOWN, TapNormalizedConfig{Name: info}
}

func (c *ForwarderConnCorrelations) VppIfToInfo(cluster, node, pod string, vppIf VppInterface) *ForwarderIf {
	ifType, ifConfig := c.vppInterfaceInfo(vppIf)
	iface := vppIf.Value
	return &ForwarderIf {
		Owner: IfOwner{
			Cluster: cluster,
			Node:    node,
			Pod:     pod,
		},
		IfContextType: ForwarderContextVPP,
		IfName: iface.Name,
		InternalIfName: interfaceInternalName(vppIf),
		NormalizedType: ifType,
		NormalizedConfig: ifConfig,
	}
}

func (c *ForwarderConnCorrelations) AddForwarderIf(intf *ForwarderIf) {
	// Add interconnects to type sorted map
	if _, ok := c.IfInterconnects[intf.NormalizedType]; !ok {
		c.IfInterconnects[intf.NormalizedType] = make(map[string][]*ForwarderIf)
	}
	intfMatchKey := intf.NormalizedConfig.MatchKey()
	if _, ok := c.IfInterconnects[intf.NormalizedType][intfMatchKey]; !ok {
		c.IfInterconnects[intf.NormalizedType][intfMatchKey] = []*ForwarderIf{}
	}
	c.IfInterconnects[intf.NormalizedType][intfMatchKey] =
		append(c.IfInterconnects[intf.NormalizedType][intfMatchKey], intf)

	// add to pod sorted map
	if _, ok := c.PodIfs[intf.Owner.Pod]; !ok {
		c.PodIfs[intf.Owner.Pod] = make(map[string]*ForwarderIf)
	}
	c.PodIfs[intf.Owner.Pod][intf.IfName] = intf
}

func (c *ForwarderConnCorrelations) AddIfXconnects(pod string, instance *Instance) {
	if _, ok := c.IfXconnects[pod]; !ok {
		c.IfXconnects[pod] = make(map[string]string)
	}
	for _, xconn := range instance.Config.VPP.L2XConnects {
		c.IfXconnects[pod][xconn.Value.ReceiveInterface] = xconn.Value.TransmitInterface
		c.IfXconnects[pod][xconn.Value.TransmitInterface] = xconn.Value.ReceiveInterface
	}
}

func (c *ForwarderConnCorrelations) GetPodIntf(pod, ifName string) *ForwarderIf {
	if _, ok := c.PodIfs[pod]; !ok {
		logrus.Warnf("No pod found named '%s' in lookup for interface named '%s'", pod, ifName)
		return nil
	}
	intf, ok := c.PodIfs[pod][ifName]
	if !ok {
		logrus.Warnf("No interface named '%s' found in pod named '%s'", ifName, pod)
		return nil
	}
	return intf
}

func (c *ForwarderConnCorrelations) IfToInterconnectPeer(intf *ForwarderIf) *ForwarderIf {
	interConnIntfs, ok := c.IfInterconnects[intf.NormalizedType][intf.NormalizedConfig.MatchKey()]
	if !ok {
		logrus.Errorf("No interconnect for interface '%s/%s' type %s with MatchKey '%s'",
			intf.Owner.Pod, intf.IfName, intf.NormalizedType.String(),
			intf.NormalizedConfig.MatchKey())
		return nil
	}
	for _, interconIntf := range interConnIntfs {
		if interconIntf.Owner != intf.Owner {
			return interconIntf
		}
	}
	return nil
}

func (c *ForwarderConnCorrelations) IfToXconnVwireChain(intf *ForwarderIf) []*ForwarderIf {

	isEnd := false
	curIf := intf
	vWireChain := []*ForwarderIf{ intf }
	for !isEnd {
		if xconnPeerIfName, ok := c.IfXconnects[curIf.Owner.Pod][curIf.IfName]; !ok {
			isEnd = true
			break
		} else {
			// xconnects are on same pod so lookup the xconnPeerIfName for the same pod as curIf
			peerIntf := c.GetPodIntf(curIf.Owner.Pod, xconnPeerIfName)
			if peerIntf != nil {
				vWireChain = append(vWireChain, peerIntf)
			}
			// go to the peerIntf's interconnect
			interConnIntf := c.IfToInterconnectPeer(peerIntf)
			if interConnIntf == nil {
				logrus.Errorf("No interconnect for interface '%s/%s' type %s with MatchKey '%s'",
					peerIntf.Owner.Pod, peerIntf.IfName, peerIntf.NormalizedType.String(),
					peerIntf.NormalizedConfig.MatchKey())
				isEnd = true
				break
			}
			vWireChain = append(vWireChain, interConnIntf)
			curIf = interConnIntf
		}
	}
	return vWireChain
}

func (c *ForwarderConnCorrelations) VppInstanceToIfs(cluster, node, pod string, instance *Instance) ([]*ForwarderIf, error) {
	var ifs []*ForwarderIf

	if len(instance.Config.VPP.Interfaces) > 0 {
		for _, v := range instance.Config.VPP.Interfaces {
			intf := c.VppIfToInfo(cluster, node, pod, v)
			ifs = append(ifs, intf)
			c.AddForwarderIf(intf)
		}
	}
	if len(instance.Config.Linux.Interfaces) > 0 {
		for _, l := range instance.Config.Linux.Interfaces {
			intf := c.LinuxIfToInfo(cluster, node, pod, l)
			ifs = append(ifs, intf)
			c.AddForwarderIf(intf)
		}
	}

	c.AddIfXconnects(pod, instance)

	return ifs, nil
}

func (c *ForwarderConnCorrelations) AddConnectionChain(chainType ForwarderConnectionType, conChain []*ForwarderIf) {
	newConn := &ForwarderConnection{
		Type: chainType,
		IntfPath: conChain,
	}
	c.Connections = append(c.Connections, newConn)
	for _, intf := range conChain {
		intf.CorrelatedConnection = newConn
	}
}

// Build Connection Chains
//  1) start with IfInterconnects[TAP]
//     - Linux intf <-> vpp intf
//  2) find IfXconnects[vpp intf]
//     -                         <-xconn-> peer vpp intf
//  3) find IfInterconnects[peerIf type][peerIf matchkey]
//                                                       <-> peer pod intf
//  4) it may stop there but repeat steps 2, 3, 4 if xconn and/or interconn
//
//  repeat step 1 for any IfInterconnects[Memif] interfaces not in a prior chain
func (c *ForwarderConnCorrelations) BuildConnectionChains() {
	// Keep track of interfaces used in connection chain
	//usedIntfs := make(map[string]*ForwarderIf) // key = pod/ifName

	for _, tapInterConn := range c.IfInterconnects[TAP] {
		var curChain []*ForwarderIf
		var startXconIntf *ForwarderIf
		// Start at Linux owned interfaces as head of chain
		if len(tapInterConn) < 2 {
			if len(tapInterConn) == 1 {
				logrus.Warnf("Interconnect with intf %s/%s not fully built--len %d",
					tapInterConn[0].Owner.Pod, tapInterConn[0].IfName, len(tapInterConn))
			} else {
				logrus.Errorf("TAP Interconnect empty--len %d", len(tapInterConn))
				continue
			}
			startXconIntf = tapInterConn[0]
		} else {
			var firstIntf *ForwarderIf
			if tapInterConn[0].IfContextType == ForwarderContextLinux {
				firstIntf = tapInterConn[0]
				startXconIntf = tapInterConn[1]
			} else {
				firstIntf = tapInterConn[1]
				startXconIntf = tapInterConn[0]
			}
			curChain = append(curChain, firstIntf)
		}
		curChain = append(curChain, c.IfToXconnVwireChain(startXconIntf)...)
		c.AddConnectionChain(TapHead, curChain)
	}

	for _, memifInterConn := range c.IfInterconnects[MEMIF] {
		var curChain []*ForwarderIf
		var startXconIntf *ForwarderIf
		// Start at memif with no xconn as head of chain
		if len(memifInterConn) < 2 {
			if len(memifInterConn) == 1 {
				logrus.Warnf("Interconnect with intf %s/%s not fully built--len %d",
					memifInterConn[0].Owner.Pod, memifInterConn[0].IfName, len(memifInterConn))
			} else {
				logrus.Errorf("memif Interconnect empty--len %d", len(memifInterConn))
				continue
			}
			startXconIntf = memifInterConn[0]
		} else {
			var firstIntf *ForwarderIf
			// firstIntf is one with no xconnect
			if _, ok := c.IfXconnects[memifInterConn[0].Owner.Pod]; !ok {
				firstIntf = memifInterConn[0]
				startXconIntf = memifInterConn[1]
			} else if _, ok := c.IfXconnects[memifInterConn[0].Owner.Pod][memifInterConn[0].IfName]; !ok {
				firstIntf = memifInterConn[0]
				startXconIntf = memifInterConn[1]
			} else {
				// lazily assumes the other memif is the one with no xconnect
				firstIntf = memifInterConn[1]
				startXconIntf = memifInterConn[0]
			}
			curChain = append(curChain, firstIntf)
		}
		if startXconIntf.CorrelatedConnection != nil {
			logrus.Infof("Connection correlation already done for starting intf %s/%s",
				startXconIntf.Owner.Pod, startXconIntf.IfName)
			continue
		}
		curChain = append(curChain, c.IfToXconnVwireChain(startXconIntf)...)
		c.AddConnectionChain(MemifHead, curChain)
	}

	// Add any dangling vxlan interconnects that are not part of tap/memif connections
	for _, vxlanifInterConn := range c.IfInterconnects[VXLAN] {
		if vxlanifInterConn[0].CorrelatedConnection ==  nil {
			// This vxlan wasn't correlated to a connection
			// add it to a connection with its interconnect
			var curChain []*ForwarderIf
			for _, intf := range vxlanifInterConn {
				curChain = append(curChain, intf)
			}
			c.AddConnectionChain(VxlanHead, curChain)
		}
	}
}

//
// Interface Mappings
//   1) interconnects -- e.g. both sides of tap, both sides of vxlan, or both sides of memif
//   2) crossconnects -- e.g. switch mapping within a forwarder

func (c *ForwarderConnCorrelations) MapIntfs() {
	for _, instance := range c.instances {
		metadata := instance.handler.Metadata()
		node := metadata["node"]
		podname := metadata["pod"]
		cluster := metadata["cluster"]

		// Normalize info on all interfaces handled by each vpp instance
		forwarderIfs, err := c.VppInstanceToIfs(cluster, node, podname, instance)
		if err != nil {
			logrus.Errorf("Failed to correlate intf data for %s/%s/%s (cluster/node/pod): %v", metadata["cluster"], node, podname, err)
			continue
		}
		c.AllIfs = append(c.AllIfs, forwarderIfs...)
	}
}

func CorrelateNsmForwarderConnections(instances []*Instance) (*ForwarderConnCorrelations, error) {

	data, err := newForwarderConnCorrelations(instances)
	if err != nil {
		return nil, fmt.Errorf("Failed to create intf data for instances: %v", err)
	}

	data.MapIntfs()

	data.BuildConnectionChains()

	return data, nil
}