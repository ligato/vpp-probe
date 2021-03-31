package topology

import (
	"fmt"

	"github.com/sirupsen/logrus"
	linux_interfaces "go.ligato.io/vpp-agent/v3/proto/ligato/linux/interfaces"
	vpp_interfaces "go.ligato.io/vpp-agent/v3/proto/ligato/vpp/interfaces"
	"go.ligato.io/vpp-probe/vpp"
	"go.ligato.io/vpp-probe/vpp/agent"
)

type Info struct {
	Networks    []Network
	Connections []*Connection
}

type Network struct {
	Linux     bool
	Namespace string
}

// Endpoint defines a communication endpoint in a network.
type Endpoint struct {
	Interface string
	Instance  string
	Network
	instance *vpp.Instance `json:"-"`
}

// Connection defines a connection between two endpoints.
// It is represented as an edge.
type Connection struct {
	Source      Endpoint
	Destination Endpoint
	Metadata    map[string]string
}

func (c Connection) String() string {
	src := c.Source.Interface
	dst := c.Destination.Interface

	if c.Source.Linux {
		src = fmt.Sprintf("LINUX-%s", src)
	}
	if c.Destination.Linux {
		dst = fmt.Sprintf("LINUX-%s", dst)
	}
	if c.Source.Namespace != "" {
		src += fmt.Sprintf("-NAMESPACE-%s", c.Source.Namespace)
	}
	if c.Destination.Namespace != "" {
		dst += fmt.Sprintf("-NAMESPACE-%s", c.Destination.Namespace)
	}
	src = fmt.Sprintf("%v_%v", c.Source.instance, src)
	dst = fmt.Sprintf("%v_%v", c.Destination.instance, dst)
	return fmt.Sprintf("%q -> %q", src, dst)
}

func Build(instances []*vpp.Instance) (*Info, error) {
	s := &scanCtx{
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
				// TODO
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

		// correlate L2 xconnects
		for _, l2xc := range instance.Agent().Config.VPP.L2XConnects {
			s.addConn("l2xconn", Endpoint{
				instance:  instance,
				Interface: l2xc.Value.TransmitInterface,
			}, Endpoint{
				instance:  instance,
				Interface: l2xc.Value.ReceiveInterface,
			})
		}

	}

	info := &Info{
		Connections: s.connections,
	}

	return info, nil
}

type scanCtx struct {
	instances   []*vpp.Instance
	connections []*Connection
}

func (s *scanCtx) addConn(typ string, src, dst Endpoint) *Connection {
	src.Instance = src.instance.ID()
	dst.Instance = dst.instance.ID()
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

func (s *scanCtx) correlateMemif(instance *vpp.Instance, ifaceIdx int) {
	iface := instance.Agent().Config.VPP.Interfaces[ifaceIdx]
	memif1 := iface.Value.GetMemif()

	log := logrus.WithFields(map[string]interface{}{
		"instance": instance.ID(),
		"ifaceIdx": ifaceIdx,
		"inode":    iface.Metadata["inode"],
	})
	log.Debugf("correlating memif interface: %v", memif1)

	for _, instance2 := range s.instances {
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
				instance:  instance,
				Interface: iface.Value.GetName(),
			}, Endpoint{
				instance:  instance2,
				Interface: iface2.Value.GetName(),
			})
		}
	}
}

func (s *scanCtx) correlateAfPacket(instance *vpp.Instance, ifaceIdx int) {
	iface := instance.Agent().Config.VPP.Interfaces[ifaceIdx]
	hostIfName := iface.Value.GetAfpacket().GetHostIfName()

	var hostIface *agent.LinuxInterface

	network := Network{
		Linux: true,
	}
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
		network.Namespace = linuxIface.Value.GetNamespace().GetReference()
	}
	if hostIface == nil {
		logrus.Warnf("could not find host interface for afpacket %v", iface)
		return
	}

	s.addConn("afpacket-to-host", Endpoint{
		instance:  instance,
		Interface: iface.Value.Name,
	}, Endpoint{
		instance:  instance,
		Interface: hostIface.Value.GetName(),
		Network:   network,
	})
	s.addConn("host-to-afpacket", Endpoint{
		instance:  instance,
		Interface: hostIface.Value.GetName(),
		Network:   network,
	}, Endpoint{
		instance:  instance,
		Interface: iface.Value.Name,
	})
}

func (s *scanCtx) correlateVeth(instance *vpp.Instance, ifaceIdx int) {
	iface := instance.Agent().Config.Linux.Interfaces[ifaceIdx]

	veth2 := instance.Agent().Config.GetLinuxInterface(iface.Value.GetVeth().PeerIfName)
	if veth2 == nil {
		logrus.Warnf("could not find peer veth for: %v", iface)
		return
	}

	network := Network{
		Linux:     true,
		Namespace: iface.Value.GetNamespace().GetReference(),
	}
	network2 := Network{
		Linux:     true,
		Namespace: veth2.Value.GetNamespace().GetReference(),
	}

	s.addConn("veth-pair", Endpoint{
		instance:  instance,
		Interface: iface.Value.GetName(),
		Network:   network,
	}, Endpoint{
		instance:  instance,
		Interface: veth2.Value.GetName(),
		Network:   network2,
	})
}

func (s *scanCtx) correlateVxlanTunnel(instance *vpp.Instance, ifaceIdx int) {
	iface := instance.Agent().Config.VPP.Interfaces[ifaceIdx]

	vxlan := iface.Value.GetVxlan()
	srcAddr := vxlan.GetSrcAddress()
	dstAddr := vxlan.GetDstAddress()

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
				instance:  instance,
				Interface: iface.Value.Name,
			}, Endpoint{
				instance:  instance2,
				Interface: iface2.Value.Name,
			})
		}
	}
}

func (s *scanCtx) correlateTapToVPP(instance *vpp.Instance, ifaceIdx int) {
	iface := instance.Agent().Config.Linux.Interfaces[ifaceIdx]

	tap2 := instance.Agent().Config.GetVppInterface(iface.Value.GetTap().VppTapIfName)
	if tap2 == nil {
		logrus.Warnf("could not find vpp tap for: %v", iface)
		return
	}

	network := Network{
		Linux:     true,
		Namespace: iface.Value.GetNamespace().GetReference(),
	}

	s.addConn("host-to-tap", Endpoint{
		instance:  instance,
		Interface: iface.Value.Name,
		Network:   network,
	}, Endpoint{
		instance:  instance,
		Interface: tap2.Value.GetName(),
	})
	s.addConn("tap-to-host", Endpoint{
		instance:  instance,
		Interface: tap2.Value.GetName(),
	}, Endpoint{
		instance:  instance,
		Interface: iface.Value.Name,
		Network:   network,
	})
}
