package topology

import (
	"github.com/sirupsen/logrus"
	linux_interfaces "go.ligato.io/vpp-agent/v3/proto/ligato/linux/interfaces"
	vpp_interfaces "go.ligato.io/vpp-agent/v3/proto/ligato/vpp/interfaces"

	"go.ligato.io/vpp-probe/vpp"
	"go.ligato.io/vpp-probe/vpp/agent"
)

func Build(instances []*vpp.Instance) (*Info, error) {
	s := newBuildCtx(instances)

	logrus.Debugf("building topology info for %v instances", len(instances))

	for _, instance := range instances {
		logrus.Debugf("correlating instance: %+v", instance)

		// correlate VPP interfaces
		for i, iface := range instance.Agent().Config.VPP.Interfaces {
			switch iface.Value.GetType() {
			case vpp_interfaces.Interface_MEMIF:
				s.correlateMemif(instance, i)
			case vpp_interfaces.Interface_AF_PACKET:
				s.correlateAfPacket(instance, i)
			case vpp_interfaces.Interface_TAP:
				s.correlateTapToHost(instance, i)
			case vpp_interfaces.Interface_VXLAN_TUNNEL:
				s.correlateVxlanTunnel(instance, i)
			default:
				logrus.Debugf("correlation for vpp interface type %v not implemented", iface.Value.GetType())
			}
		}

		// correlate Linux interfaces
		for i, iface := range instance.Agent().Config.Linux.Interfaces {
			switch iface.Value.GetType() {
			case linux_interfaces.Interface_VETH:
				s.correlateVeth(instance, i)
			case linux_interfaces.Interface_TAP_TO_VPP:
				s.correlateTapToVPP(instance, i)
			default:
				logrus.Debugf("correlation for linux interface type %v not implemented", iface.Value.GetType())
			}
		}

		// correlate other relations
		if l2xconnects := instance.Agent().Config.VPP.L2XConnects; len(l2xconnects) > 0 {
			s.correlateL2xconnects(instance, l2xconnects)
		}
	}

	info := &Info{
		Connections: s.connections,
	}

	return info, nil
}

type buildCtx struct {
	instances   []*vpp.Instance
	connections []*Connection
}

func newBuildCtx(instances []*vpp.Instance) *buildCtx {
	return &buildCtx{instances: instances}
}

func (s *buildCtx) addConn(typ string, src, dst Endpoint) *Connection {
	conn := &Connection{
		Source:      src,
		Destination: dst,
		Metadata: map[string]string{
			"type": typ,
		},
	}
	s.connections = append(s.connections, conn)
	return conn
}

func (s *buildCtx) correlateMemif(instance *vpp.Instance, ifaceIdx int) {
	iface := instance.Agent().Config.VPP.Interfaces[ifaceIdx]
	memif1 := iface.Value.GetMemif()

	log := logrus.WithFields(map[string]interface{}{
		"instance": instance.ID(),
		"ifaceIdx": ifaceIdx,
		"inode":    iface.Metadata["inode"],
	})
	log.Debugf("correlating memif interface: %v", memif1)

	memifEndpoint := &Endpoint{
		Network:   newVppNetwork(instance),
		Interface: iface.Value.GetName(),
	}
	memifEndpoint.addMetadata("state", getVppIfaceState(&iface))

	var conns []*Connection

	for _, instance2 := range s.instances {
		vppNetwork2 := newVppNetwork(instance2)
		for i, iface2 := range instance2.Agent().Config.VPP.Interfaces {
			if instance.ID() == instance2.ID() && (i == ifaceIdx || iface.Key == iface2.Key) {
				continue
			}
			if iface2.Value.GetType() != vpp_interfaces.Interface_MEMIF {
				continue
			}

			memif2 := iface2.Value.GetMemif()

			log.Debugf("found matching memif interface on instance %v: %+v", instance2, memif2)

			if memif1.GetId() != memif2.GetId() {
				continue
			}
			if iface.Metadata["inode"] != iface2.Metadata["inode"] {
				continue
			}

			log.Debugf("found matching memif interface on instance %v: %+v", instance2, memif2)

			conn := s.addConn("memif-sock", *memifEndpoint, Endpoint{
				Network:   vppNetwork2,
				Interface: iface2.Value.GetName(),
			})

			conns = append(conns, conn)
		}
	}

	if len(conns) == 0 {
		s.addConn("memif-sock", *memifEndpoint, Endpoint{
			Interface: memif1.GetSocketFilename(),
		}).addMetadata("state", "down")
	}
}

func (s *buildCtx) correlateAfPacket(instance *vpp.Instance, ifaceIdx int) {
	iface := instance.Agent().Config.VPP.Interfaces[ifaceIdx]
	afPacket := iface.Value.GetAfpacket()

	hostIfName := afPacket.GetHostIfName()

	log := logrus.WithFields(map[string]interface{}{
		"instance":   instance.ID(),
		"ifaceIdx":   ifaceIdx,
		"hostIfName": hostIfName,
	})
	log.Debugf("correlating afpacket interface: %v", afPacket)

	var hostIface *agent.LinuxInterface

	for _, linuxIface := range instance.Agent().Config.Linux.Interfaces {
		if linuxIface.Value.GetHostIfName() != hostIfName {
			continue
		}
		if hostIface != nil {
			log.Warnf("found more than one host interface for afpacket %v", iface)
			continue
		}
		ifc := linuxIface
		hostIface = &ifc
	}
	if hostIface == nil {
		log.Warnf("could not find host interface for afpacket %v", iface)
		return
	}

	afPacketEndpoint := Endpoint{
		Network:   newVppNetwork(instance),
		Interface: iface.Value.GetName(),
	}
	vethEndpoint := Endpoint{
		Network:   newLinuxNetwork(instance, hostIface.Value.GetNamespace().GetReference()),
		Interface: hostIface.Value.GetName(),
	}

	s.addConn("afpacket-to-host", afPacketEndpoint, vethEndpoint)
	s.addConn("host-to-afpacket", vethEndpoint, afPacketEndpoint)
}

func (s *buildCtx) correlateVeth(instance *vpp.Instance, ifaceIdx int) {
	iface := instance.Agent().Config.Linux.Interfaces[ifaceIdx]
	veth := iface.Value.GetVeth()

	log := logrus.WithFields(map[string]interface{}{
		"instance":   instance.ID(),
		"ifaceIdx":   ifaceIdx,
		"peerIfName": veth.PeerIfName,
	})
	log.Debugf("correlating veth interface: %v", veth)

	iface2 := instance.Agent().Config.GetLinuxInterface(iface.Value.GetVeth().PeerIfName)
	if iface2 == nil {
		log.Warnf("could not find veth peer for interface: %v", iface)
		return
	}

	s.addConn("veth-pair", Endpoint{
		Network:   newLinuxNetwork(instance, iface.Value.GetNamespace().GetReference()),
		Interface: iface.Value.GetName(),
	}, Endpoint{
		Network:   newLinuxNetwork(instance, iface2.Value.GetNamespace().GetReference()),
		Interface: iface2.Value.GetName(),
	})
}

func (s *buildCtx) correlateVxlanTunnel(instance *vpp.Instance, ifaceIdx int) {
	iface := instance.Agent().Config.VPP.Interfaces[ifaceIdx]
	vxlan := iface.Value.GetVxlan()

	log := logrus.WithFields(map[string]interface{}{
		"instance": instance.ID(),
		"ifaceIdx": ifaceIdx,
	})
	log.Debugf("correlating vxlan tunnel interface: %v", vxlan)

	srcAddr := vxlan.GetSrcAddress()
	dstAddr := vxlan.GetDstAddress()

	for _, instance2 := range s.instances {
		for _, iface2 := range instance2.Agent().Config.VPP.Interfaces {
			if instance.ID() == instance2.ID() && iface.Key == iface2.Key {
				continue // skip this interface
			}
			if iface2.Value.GetType() != vpp_interfaces.Interface_VXLAN_TUNNEL {
				continue // skip non-vxlan tunnel interfaces
			}

			vxlan2 := iface2.Value.GetVxlan()
			if vxlan.GetVni() != vxlan2.GetVni() {
				continue // skip different vni
			}
			if srcAddr != vxlan2.GetDstAddress() || dstAddr != vxlan2.GetSrcAddress() {
				continue // skip different src/dst addresses
			}

			s.addConn("vxlan-tun", Endpoint{
				Network:   newVppNetwork(instance),
				Interface: iface.Value.Name,
			}, Endpoint{
				Network:   newVppNetwork(instance2),
				Interface: iface2.Value.Name,
			})
		}
	}
}

func (s *buildCtx) correlateTapToVPP(instance *vpp.Instance, ifaceIdx int) {
	iface := instance.Agent().Config.Linux.Interfaces[ifaceIdx]
	tapToVPP := iface.Value.GetTap()

	log := logrus.WithFields(map[string]interface{}{
		"instance": instance.ID(),
		"ifaceIdx": ifaceIdx,
	})
	log.Debugf("correlating tap to vpp interface: %v", tapToVPP)

	iface2 := instance.Agent().Config.GetVppInterface(tapToVPP.GetVppTapIfName())
	if iface2 == nil {
		log.Warnf("could not find vpp tap for: %v", iface)
		return
	}

	s.addConn("host-to-tap", Endpoint{
		Network:   newLinuxNetwork(instance, iface.Value.GetNamespace().GetReference()),
		Interface: iface.Value.Name,
	}, Endpoint{
		Network:   newVppNetwork(instance),
		Interface: iface2.Value.GetName(),
	})
}

func (s *buildCtx) correlateTapToHost(instance *vpp.Instance, ifaceIdx int) {
	iface := instance.Agent().Config.VPP.Interfaces[ifaceIdx]
	tap := iface.Value.GetTap()

	log := logrus.WithFields(map[string]interface{}{
		"instance": instance.ID(),
		"ifaceIdx": ifaceIdx,
	})
	log.Debugf("correlating vpp tap interface: %v", tap)

	var hostIface *agent.LinuxInterface

	for _, linuxIface := range instance.Agent().Config.Linux.Interfaces {
		if linuxIface.Value.GetTap().GetVppTapIfName() != iface.Value.GetName() {
			continue
		}
		if hostIface != nil {
			log.Warnf("found more than one host interface for tap %v", iface)
			continue
		}
		ifc := linuxIface
		hostIface = &ifc
	}
	if hostIface == nil {
		log.Warnf("could not find host interface for tap %v", iface)
		return
	}

	s.addConn("tap-to-host", Endpoint{
		Network:   newVppNetwork(instance),
		Interface: iface.Value.GetName(),
	}, Endpoint{
		Network:   newLinuxNetwork(instance, hostIface.Value.GetNamespace().GetReference()),
		Interface: iface.Value.GetName(),
	})
}

func (s *buildCtx) correlateL2xconnects(instance *vpp.Instance, l2xconnects []agent.VppL2XConnect) {
	log := logrus.WithFields(map[string]interface{}{
		"instance": instance.ID(),
	})
	log.Debugf("correlating %d l2xconnects", len(l2xconnects))

	vppNetwork := newVppNetwork(instance)

	for _, l2xc := range instance.Agent().Config.VPP.L2XConnects {
		s.addConn("l2xconn", Endpoint{
			Network:   vppNetwork,
			Interface: l2xc.Value.GetTransmitInterface(),
		}, Endpoint{
			Network:   vppNetwork,
			Interface: l2xc.Value.GetReceiveInterface(),
		})
	}
}

func getVppIfaceState(iface *agent.VppInterface) string {
	if !iface.Value.GetEnabled() {
		return "down"
	}
	if !iface.GetLinkState() {
		return "link down"
	}
	return "up"
}
