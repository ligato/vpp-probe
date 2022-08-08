package binapi

import (
	"encoding/binary"
	"fmt"
	"math"
	"strings"
	"time"

	"go.ligato.io/vpp-agent/v3/plugins/vpp/binapi/vpp2106/interface_types"
	"go.ligato.io/vpp-agent/v3/plugins/vpp/binapi/vpp2106/vpe"
	"go.ligato.io/vpp-agent/v3/plugins/vpp/binapi/vpp2106/vpe_types"

	"go.ligato.io/vpp-probe/vpp/api"
)

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

func vppLogLevelToString(level vpe_types.LogLevel) string {
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

const (
	logTimeFormat = "2006/01/02 15:04:05.000"
)

func formatLogLine(log *vpe.LogDetails) string {
	ts := timestampToTime(fixTimestamp(log.Timestamp)).Format(logTimeFormat)
	logLevel := vppLogLevelToString(log.Level)
	return fmt.Sprintf("%v %s  %s  %s", ts, logLevel, log.MsgClass, log.Message)
}

func newTimestamp(t time.Time) vpe_types.Timestamp {
	if t.IsZero() {
		return 0
	}
	sec := int64(t.Unix())
	nsec := int32(t.Nanosecond())
	ns := float64(sec) + float64(nsec/1e9)
	return vpe_types.Timestamp(ns)
}

func timestampToTime(timestamp vpe_types.Timestamp) time.Time {
	ns := int64(timestamp * 1e9)
	sec := ns / 1e9
	nsec := ns % 1e9
	return time.Unix(sec, nsec)
}

func fixTimestamp(timestamp vpe_types.Timestamp) vpe_types.Timestamp {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, math.Float64bits(float64(timestamp)))
	v := math.Float64frombits(binary.LittleEndian.Uint64(b))
	return vpe_types.Timestamp(v)
}
