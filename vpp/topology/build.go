package topology

import (
	"github.com/sirupsen/logrus"
	linux_interfaces "go.ligato.io/vpp-agent/v3/proto/ligato/linux/interfaces"
	vpp_interfaces "go.ligato.io/vpp-agent/v3/proto/ligato/vpp/interfaces"

	"go.ligato.io/vpp-probe/vpp"
	"go.ligato.io/vpp-probe/vpp/agent"
)

func Build(instances []*vpp.Instance) (*Info, error) {
	s := &buildCtx{
		instances: instances,
	}

	logrus.Debugf("starting correlation for %v interfaces", len(instances))

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
			}
		}

		// correlate Linux interfaces
		for i, iface := range instance.Agent().Config.Linux.Interfaces {
			switch iface.Value.GetType() {
			case linux_interfaces.Interface_VETH:
				s.correlateVeth(instance, i)
			case linux_interfaces.Interface_TAP_TO_VPP:
				s.correlateTapToVPP(instance, i)
			}
		}

		// correlate other relations
		s.correlateL2xconnects(instance)
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

			s.addConn("memif-sock", Endpoint{
				Network:   newVppNetwork(instance),
				Interface: iface.Value.GetName(),
			}, Endpoint{
				Network:   vppNetwork2,
				Interface: iface2.Value.GetName(),
			}).addMetadata("state", getVppIfaceState(&iface))
		}
	}
}

func (s *buildCtx) correlateAfPacket(instance *vpp.Instance, ifaceIdx int) {

	iface := instance.Agent().Config.VPP.Interfaces[ifaceIdx]
	hostIfName := iface.Value.GetAfpacket().GetHostIfName()

	var hostIface *agent.LinuxInterface

	linuxNetwork := newLinuxNetwork(instance, "")
	for _, linuxIface := range instance.Agent().Config.Linux.Interfaces {
		if linuxIface.Value.GetHostIfName() != hostIfName {
			continue
		}
		if hostIface != nil {
			logrus.Warnf("found more than one host interface for afpacket %v", iface)
			continue
		}
		ifc := linuxIface
		hostIface = &ifc
		linuxNetwork.Namespace = linuxIface.Value.GetNamespace().GetReference()
	}
	if hostIface == nil {
		logrus.Warnf("could not find host interface for afpacket %v", iface)
		return
	}

	afPacketEndpoint := Endpoint{
		Network:   newVppNetwork(instance),
		Interface: iface.Value.Name,
	}
	vethEndpoint := Endpoint{
		Network:   linuxNetwork,
		Interface: hostIface.Value.GetName(),
	}

	s.addConn("afpacket-to-host", afPacketEndpoint, vethEndpoint).
		addMetadata("state", getVppIfaceState(&iface))

	s.addConn("host-to-afpacket", vethEndpoint, afPacketEndpoint)
}

func (s *buildCtx) correlateVeth(instance *vpp.Instance, ifaceIdx int) {
	iface := instance.Agent().Config.Linux.Interfaces[ifaceIdx]

	iface2 := instance.Agent().Config.GetLinuxInterface(iface.Value.GetVeth().PeerIfName)
	if iface2 == nil {
		logrus.Warnf("could not find peer veth for: %v", iface)
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
	srcAddr := vxlan.GetSrcAddress()
	dstAddr := vxlan.GetDstAddress()

	logrus.Tracef("correlating vxlan tunnel")

	for _, instance2 := range s.instances {
		for _, iface2 := range instance2.Agent().Config.VPP.Interfaces {
			if instance.ID() == instance2.ID() && iface.Key == iface2.Key {
				continue
			}
			if iface2.Value.GetType() != vpp_interfaces.Interface_VXLAN_TUNNEL {
				continue
			}

			vxlan2 := iface2.Value.GetVxlan()
			if vxlan.GetVni() != vxlan2.GetVni() {
				continue
			}
			if srcAddr != vxlan2.GetDstAddress() || dstAddr != vxlan2.GetSrcAddress() {
				continue
			}

			s.addConn("vxlan-tun", Endpoint{
				Network:   newVppNetwork(instance),
				Interface: iface.Value.Name,
			}, Endpoint{
				Network:   newVppNetwork(instance2),
				Interface: iface2.Value.Name,
			}).addMetadata("state", getVppIfaceState(&iface))
		}
	}
}

func (s *buildCtx) correlateTapToVPP(instance *vpp.Instance, ifaceIdx int) {
	iface := instance.Agent().Config.Linux.Interfaces[ifaceIdx]

	iface2 := instance.Agent().Config.GetVppInterface(iface.Value.GetTap().VppTapIfName)
	if iface2 == nil {
		logrus.Warnf("could not find vpp tap for: %v", iface)
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

	var hostIface *agent.LinuxInterface

	network := newLinuxNetwork(instance, "")
	for _, linuxIface := range instance.Agent().Config.Linux.Interfaces {
		if linuxIface.Value.GetTap().GetVppTapIfName() != iface.Value.GetName() {
			continue
		}
		if hostIface != nil {
			logrus.Warnf("found more than one host interface for tap %v", iface)
			continue
		}
		ifc := linuxIface
		hostIface = &ifc
		network.Namespace = linuxIface.Value.GetNamespace().GetReference()
	}
	if hostIface == nil {
		logrus.Warnf("could not find host interface for tap %v", iface)
		return
	}

	s.addConn("tap-to-host", Endpoint{
		Network:   newVppNetwork(instance),
		Interface: iface.Value.GetName(),
	}, Endpoint{
		Network:   network,
		Interface: iface.Value.GetName(),
	}).addMetadata("state", getVppIfaceState(&iface))
}

func (s *buildCtx) correlateL2xconnects(instance *vpp.Instance) {
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
