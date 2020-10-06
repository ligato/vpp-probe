package vpp

import (
	"fmt"
	"net"
	"strings"

	"go.ligato.io/vpp-agent/v3/plugins/vpp/binapi/vpp2001/interface_types"
	"go.ligato.io/vpp-agent/v3/plugins/vpp/binapi/vpp2001/interfaces"
	"go.ligato.io/vpp-agent/v3/plugins/vpp/binapi/vpp2001/ip_types"
	"go.ligato.io/vpp-agent/v3/plugins/vpp/binapi/vpp2001/vpe"

	"go.ligato.io/vpp-probe/client"
)

func vppL2AddrToString(mac interfaces.MacAddress) string {
	return net.HardwareAddr(mac[:]).String()
}

func vppPrefixToString(x ip_types.AddressWithPrefix) string {
	ipaddr := vppAddressToIP(x.Address)
	return fmt.Sprintf("%s/%d", ipaddr, x.Len)
}

func vppAddressToIP(x ip_types.Address) net.IP {
	if x.Af == ip_types.ADDRESS_IP6 {
		ip6 := x.Un.GetIP6()
		return net.IP(ip6[:]).To16()
	} else {
		ip4 := x.Un.GetIP4()
		return net.IP(ip4[:]).To4()
	}
}

func vppIfTypeToString(ifType interface_types.IfType) string {
	const (
		IfTypePrefix = "IF_API_TYPE_"
	)
	typ := strings.TrimPrefix(ifType.String(), IfTypePrefix)
	return strings.ToLower(typ)
}

func vppIfStatusFlagsToString(status interface_types.IfStatusFlags) string {
	const (
		LinkUp  = interface_types.IF_STATUS_API_FLAG_LINK_UP
		AdminUp = interface_types.IF_STATUS_API_FLAG_ADMIN_UP
	)
	var (
		linkUp  = status&LinkUp == LinkUp
		adminUp = status&AdminUp == AdminUp
	)
	switch {
	case adminUp && linkUp:
		return "up"
	case linkUp:
		return "down (link up)"
	case adminUp:
		return "down (admin up)"
	case !adminUp && !linkUp:
		return "down"
	default:
		return fmt.Sprint(status)
	}
}

func vppLogLevelToString(level vpe.LogLevel) string {
	const logLevelPrefix = "VPE_API_LOG_LEVEL_"
	return strings.TrimPrefix(level.String(), logLevelPrefix)
}

func vppInterfaceMTU(mtu []uint32, link uint16) client.MTU {
	return client.MTU{
		L3:   uint(mtu[0]),
		IP4:  uint(mtu[1]),
		IP6:  uint(mtu[2]),
		MPLS: uint(mtu[3]),
		Link: uint(link),
	}
}
