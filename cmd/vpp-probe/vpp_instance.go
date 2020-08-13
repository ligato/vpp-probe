package main

import (
	"fmt"
	"sort"

	"github.com/gookit/color"
	linux_interfaces "go.ligato.io/vpp-agent/v3/proto/ligato/linux/interfaces"
	vpp_interfaces "go.ligato.io/vpp-agent/v3/proto/ligato/vpp/interfaces"
)

type VppInstance struct {
	Pod             Pod
	Version         string
	Interfaces      []*VppInterface
	LinuxInterfaces []*LinuxInterface
	Extra           map[string]string
}

type LinuxInterface struct {
	Value    *linux_interfaces.Interface
	Key      string
	Metadata map[string]interface{}
	Origin   uint
}

type VppInterface struct {
	Value    *vpp_interfaces.Interface
	Key      string
	Metadata map[string]interface{}
	Origin   uint
}

func (iface *VppInterface) Info() string {
	switch iface.Value.Type {
	case vpp_interfaces.Interface_MEMIF:
		memif := iface.Value.GetMemif()
		var info string
		info += fmt.Sprintf("socket:%s ", escapeClr(color.LightYellow, memif.SocketFilename))
		if memif.Id > 0 {
			info += fmt.Sprintf("ID:%d ", memif.Id)
		}
		if memif.Master {
			info += fmt.Sprintf("master:%s ", escapeClr(color.LightYellow, memif.Master))
		}
		return info
	case vpp_interfaces.Interface_VXLAN_TUNNEL:
		vxlan := iface.Value.GetVxlan()
		var info string
		info += fmt.Sprintf("src:%s -> dst:%s (vni:%v)", escapeClr(color.LightYellow, vxlan.SrcAddress), escapeClr(color.LightYellow, vxlan.DstAddress), escapeClr(color.LightYellow, vxlan.Vni))
		return info
	case vpp_interfaces.Interface_TAP:
		tap := iface.Value.GetTap()
		return fmt.Sprintf("host_ifname:%s %v", escapeClr(color.LightYellow, iface.Metadata["TAPHostIfName"]), tap.String())
	case vpp_interfaces.Interface_AF_PACKET:
		afp := iface.Value.GetAfpacket()
		var info string
		info += fmt.Sprintf("host_if_name:%s", escapeClr(color.LightYellow, afp.HostIfName))
		return info
	}
	return fmt.Sprint(iface.Value.GetLink())
}

func hasIfaceType(ifaces []*VppInterface, typ vpp_interfaces.Interface_Type) bool {
	for _, iface := range ifaces {
		if iface.Value.Type == typ {
			return true
		}
	}
	return false
}

func sortIfaces(ifaces []VppInterface) {
	sort.Slice(ifaces, func(i, j int) bool {
		return ifaces[i].Value.Type < ifaces[j].Value.Type
	})
}
