package binapi

import (
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"strings"
	"time"

	"go.ligato.io/vpp-agent/v3/plugins/vpp/binapi/vpp2001/interface_types"
	"go.ligato.io/vpp-agent/v3/plugins/vpp/binapi/vpp2001/interfaces"
	"go.ligato.io/vpp-agent/v3/plugins/vpp/binapi/vpp2001/ip_types"
	"go.ligato.io/vpp-agent/v3/plugins/vpp/binapi/vpp2001/vpe"

	"go.ligato.io/vpp-probe/vpp/api"
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

func vppIfStatusFlagsToStatus(status interface_types.IfStatusFlags) api.Status {
	const (
		LinkUp  = interface_types.IF_STATUS_API_FLAG_LINK_UP
		AdminUp = interface_types.IF_STATUS_API_FLAG_ADMIN_UP
	)
	return api.Status{
		Up:   status&AdminUp == AdminUp,
		Link: status&LinkUp == LinkUp,
	}
}

func vppLogLevelToString(level vpe.LogLevel) string {
	const logLevelPrefix = "VPE_API_LOG_LEVEL_"
	return strings.TrimPrefix(level.String(), logLevelPrefix)
}

func vppInterfaceMTU(mtu []uint32, link uint16) api.MTU {
	return api.MTU{
		L3:   uint(mtu[0]),
		IP4:  uint(mtu[1]),
		IP6:  uint(mtu[2]),
		MPLS: uint(mtu[3]),
		Link: uint(link),
	}
}

const logTimeFormat = "2006/01/01 15:04:05.000"

func formatLogLine(log *vpe.LogDetails) string {
	ts := timestampToTime(fixTimestamp(log.Timestamp)).Format(logTimeFormat)
	logLevel := vppLogLevelToString(log.Level)
	return fmt.Sprintf("%v %s  %s  %s", ts, logLevel, log.MsgClass, log.Message)
}

func newTimestamp(t time.Time) vpe.Timestamp {
	if t.IsZero() {
		return 0
	}
	sec := int64(t.Unix())
	nsec := int32(t.Nanosecond())
	ns := float64(sec) + float64(nsec/1e9)
	return vpe.Timestamp(ns)
}

func timestampToTime(timestamp vpe.Timestamp) time.Time {
	ns := int64(timestamp * 1e9)
	sec := ns / 1e9
	nsec := ns % 1e9
	return time.Unix(sec, nsec)
}

func encodeFloat64(v float64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, math.Float64bits(v))
	return b
}

func decodeFloat64(b []byte) float64 {
	v := math.Float64frombits(binary.LittleEndian.Uint64(b))
	return v
}

func fixTimestamp(timestamp vpe.Timestamp) vpe.Timestamp {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, math.Float64bits(float64(timestamp)))
	v := math.Float64frombits(binary.LittleEndian.Uint64(b))
	return vpe.Timestamp(v)
}
