package vpp

import (
	"fmt"
	"net"
	"strings"

	"go.ligato.io/vpp-agent/v3/plugins/vpp/binapi/vpp2001/interface_types"
	"go.ligato.io/vpp-agent/v3/plugins/vpp/binapi/vpp2001/interfaces"
	"go.ligato.io/vpp-agent/v3/plugins/vpp/binapi/vpp2001/ip_types"
	"go.ligato.io/vpp-agent/v3/plugins/vpp/binapi/vpp2001/vpe"

	"go.ligato.io/vpp-probe/vpp/types"
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

func vppIfStatusFlagsToStatus(status interface_types.IfStatusFlags) types.Status {
	const (
		LinkUp  = interface_types.IF_STATUS_API_FLAG_LINK_UP
		AdminUp = interface_types.IF_STATUS_API_FLAG_ADMIN_UP
	)
	return types.Status{
		Up:   status&AdminUp == AdminUp,
		Link: status&LinkUp == LinkUp,
	}
}

func vppLogLevelToString(level vpe.LogLevel) string {
	const logLevelPrefix = "VPE_API_LOG_LEVEL_"
	return strings.TrimPrefix(level.String(), logLevelPrefix)
}

func vppInterfaceMTU(mtu []uint32, link uint16) types.MTU {
	return types.MTU{
		L3:   uint(mtu[0]),
		IP4:  uint(mtu[1]),
		IP6:  uint(mtu[2]),
		MPLS: uint(mtu[3]),
		Link: uint(link),
	}
}
