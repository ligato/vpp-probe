package binapi

import (
	"context"
	"fmt"
	"io"
	"math"
	"strings"
	"time"

	govppapi "git.fd.io/govpp.git/api"
	"github.com/sirupsen/logrus"
	_ "go.ligato.io/cn-infra/v2/logging/logrus"

	interfaces "go.ligato.io/vpp-agent/v3/plugins/vpp/binapi/vpp2005/interface"
	"go.ligato.io/vpp-agent/v3/plugins/vpp/binapi/vpp2005/interface_types"
	"go.ligato.io/vpp-agent/v3/plugins/vpp/binapi/vpp2005/ip"
	"go.ligato.io/vpp-agent/v3/plugins/vpp/binapi/vpp2005/memclnt"
	"go.ligato.io/vpp-agent/v3/plugins/vpp/binapi/vpp2005/vpe"

	_ "go.ligato.io/vpp-agent/v3/plugins/govppmux/vppcalls/vpp2001"
	_ "go.ligato.io/vpp-agent/v3/plugins/govppmux/vppcalls/vpp2005"
	_ "go.ligato.io/vpp-agent/v3/plugins/govppmux/vppcalls/vpp2009"

	"go.ligato.io/vpp-probe/vpp/api"
)

type Client struct {
	conn govppapi.Connection
	ch   govppapi.Channel
}

func GetVersionInfo(conn govppapi.Connection) (*api.BuildInfo, error) {
	version, err := GetVersion(conn)
	if err != nil {
		return nil, err
	}
	return &api.BuildInfo{
		Version: version,
	}, nil
}

func GetVersionInfoChan(ch govppapi.Channel) (*api.BuildInfo, error) {
	version, err := GetVersionChan(ch)
	if err != nil {
		return nil, err
	}
	return &api.BuildInfo{
		Version: version,
	}, nil
}

func GetSystemInfo(conn govppapi.Connection) (*api.SystemInfo, error) {
	pid, err := GetPID(conn)
	if err != nil {
		return nil, err
	}
	uptime, err := GetSystemTime(conn)
	if err != nil {
		return nil, err
	}
	return &api.SystemInfo{
		Pid:    pid,
		Uptime: uptime,
	}, nil
}

func GetSystemInfoChan(ch govppapi.Channel) (*api.SystemInfo, error) {
	pid, err := GetPIDChan(ch)
	if err != nil {
		return nil, err
	}
	uptime, err := GetSystemTimeChan(ch)
	if err != nil {
		return nil, err
	}
	return &api.SystemInfo{
		Pid:    pid,
		Uptime: uptime,
	}, nil
}

func GetVersion(conn govppapi.Connection) (string, error) {
	rpc := vpe.NewServiceClient(conn)

	reply, err := rpc.ShowVersion(context.Background(), &vpe.ShowVersion{})
	if err != nil {
		return "", err
	}

	return reply.Version, nil
}

func GetVersionChan(ch govppapi.Channel) (string, error) {
	reply := &vpe.ShowVersionReply{}

	err := ch.SendRequest(&vpe.ShowVersion{}).ReceiveReply(reply)
	if err != nil {
		return "", err
	}

	return reply.Version, nil
}

type ShowVersionData struct {
	Program        string
	Version        string
	BuildDate      string
	BuildDirectory string
}

func ShowVersion(ch govppapi.Channel) (*ShowVersionData, error) {
	reply := &vpe.ShowVersionReply{}

	err := ch.SendRequest(&vpe.ShowVersion{}).ReceiveReply(reply)
	if err != nil {
		return nil, err
	}

	data := ShowVersionData{
		Program:        reply.Program,
		Version:        reply.Version,
		BuildDate:      reply.BuildDate,
		BuildDirectory: reply.BuildDirectory,
	}

	return &data, nil
}

func GetPID(conn govppapi.Connection) (int, error) {
	rpc := vpe.NewServiceClient(conn)

	reply, err := rpc.ControlPing(context.Background(), &vpe.ControlPing{})
	if err != nil {
		return 0, err
	}

	return int(reply.VpePID), nil
}

func GetPIDChan(ch govppapi.Channel) (int, error) {
	reply := &vpe.ControlPingReply{}

	err := ch.SendRequest(&vpe.ControlPing{}).ReceiveReply(reply)
	if err != nil {
		return 0, err
	}

	return int(reply.VpePID), nil
}

func GetSystemTime(conn govppapi.Connection) (time.Duration, error) {
	rpc := vpe.NewServiceClient(conn)

	reply, err := rpc.ShowVpeSystemTime(context.Background(), &vpe.ShowVpeSystemTime{})
	if err != nil {
		return 0, err
	}

	sysTime := math.Float64bits(float64(reply.VpeSystemTime))
	uptime := time.Duration(sysTime) * time.Second

	return uptime, nil
}

func GetSystemTimeChan(ch govppapi.Channel) (time.Duration, error) {
	reply := &vpe.ShowVpeSystemTimeReply{}

	err := ch.SendRequest(&vpe.ShowVpeSystemTime{}).ReceiveReply(reply)
	if err != nil {
		return 0, err
	}

	sysTime := math.Float64bits(float64(reply.VpeSystemTime))
	uptime := time.Duration(sysTime) * time.Second

	return uptime, nil
}

func DumpLogs(conn govppapi.Connection) ([]string, error) {
	return DumpLogsSince(conn, time.Time{})
}

func DumpLogsChan(ch govppapi.Channel) ([]string, error) {
	return DumpLogsSinceChan(ch, time.Time{})
}

func DumpLogsSince(conn govppapi.Connection, t time.Time) ([]string, error) {
	rpc := vpe.NewServiceClient(conn)

	stream, err := rpc.LogDump(context.Background(), &vpe.LogDump{
		StartTimestamp: newTimestamp(t),
	})
	if err != nil {
		return nil, fmt.Errorf("DumpLog failed: %v", err)
	}
	var logs []string
	for {
		log, err := stream.Recv()
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, fmt.Errorf("DumpLog failed: %v", err)
		}
		logs = append(logs, formatLogLine(log))
	}
	return logs, nil
}

func DumpLogsSinceChan(ch govppapi.Channel, t time.Time) ([]string, error) {
	stream := ch.SendMultiRequest(&vpe.LogDump{
		StartTimestamp: newTimestamp(t),
	})

	var logs []string
	for {
		log := &vpe.LogDetails{}
		last, err := stream.ReceiveReply(log)
		if last {
			break
		} else if err != nil {
			return nil, fmt.Errorf("DumpLog failed: %v", err)
		}
		logs = append(logs, formatLogLine(log))
	}
	return logs, nil
}

func ListInterfaces(conn govppapi.Connection) ([]*api.Interface, error) {
	list, err := dumpInterfaces(conn)
	if err != nil {
		return nil, err
	}
	for _, iface := range list {
		VRFs, err := getInterfaceVRF(conn, iface.Index)
		if err != nil {
			logrus.Errorf("getting interface %d VRF failed: %v", iface.Index, err)
			return nil, err

		}
		IPs, err := getInterfaceIPs(conn, iface.Index)
		if err != nil {
			logrus.Errorf("getting interface %d IPs failed: %v", iface.Index, err)
			return nil, err
		}

		iface.IPs = IPs
		iface.VRF = *VRFs
	}
	return list, nil
}

func ListInterfacesChan(ch govppapi.Channel) ([]*api.Interface, error) {
	list, err := dumpInterfacesChan(ch)
	if err != nil {
		return nil, err
	}
	for _, iface := range list {
		VRFs, err := getInterfaceVRFChan(ch, iface.Index)
		if err != nil {
			logrus.Errorf("getting interface %d VRF failed: %v", iface.Index, err)
			return nil, err

		}
		IPs, err := getInterfaceIPsChan(ch, iface.Index)
		if err != nil {
			logrus.Errorf("getting interface %d IPs failed: %v", iface.Index, err)
			return nil, err
		}

		iface.IPs = IPs
		iface.VRF = *VRFs
	}
	return list, nil
}

func dumpInterfaces(conn govppapi.Connection) ([]*api.Interface, error) {
	rpc := interfaces.NewServiceClient(conn)

	stream, err := rpc.SwInterfaceDump(context.Background(), &interfaces.SwInterfaceDump{})
	if err != nil {
		return nil, fmt.Errorf("DumpSwInterface failed: %v", err)
	}
	var ifaces []*api.Interface
	for {
		iface, err := stream.Recv()
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, fmt.Errorf("DumpSwInterface failed: %v", err)
		}
		ifaces = append(ifaces, &api.Interface{
			Index:      uint32(iface.SwIfIndex),
			Name:       strings.Trim(iface.InterfaceName, "\x00"),
			Tag:        strings.Trim(iface.Tag, "\x00"),
			Type:       vppIfTypeToString(iface.Type),
			DeviceType: iface.InterfaceDevType,
			Status:     vppIfStatusFlagsToStatus(iface.Flags),
			MTUs:       vppInterfaceMTU(iface.Mtu, iface.LinkMtu),
			MAC:        iface.L2Address.String(),
		})
	}
	return ifaces, nil
}

func dumpInterfacesChan(ch govppapi.Channel) ([]*api.Interface, error) {
	stream := ch.SendMultiRequest(&interfaces.SwInterfaceDump{})

	var ifaces []*api.Interface
	for {
		iface := &interfaces.SwInterfaceDetails{}
		last, err := stream.ReceiveReply(iface)
		if last {
			break
		} else if err != nil {
			return nil, fmt.Errorf("DumpSwInterface failed: %v", err)
		}
		ifaces = append(ifaces, &api.Interface{
			Index:      uint32(iface.SwIfIndex),
			Name:       strings.Trim(iface.InterfaceName, "\x00"),
			Tag:        strings.Trim(iface.Tag, "\x00"),
			Type:       vppIfTypeToString(iface.Type),
			DeviceType: iface.InterfaceDevType,
			Status:     vppIfStatusFlagsToStatus(iface.Flags),
			MTUs:       vppInterfaceMTU(iface.Mtu, iface.LinkMtu),
			MAC:        iface.L2Address.String(),
		})
	}
	return ifaces, nil
}

func getInterfaceVRF(conn govppapi.Connection, index uint32) (*api.VRF, error) {
	vrf4, err := getInterfaceVRFTable(conn, index, false)
	if err != nil {
		return nil, err
	}
	vrf6, err := getInterfaceVRFTable(conn, index, true)
	if err != nil {
		return nil, err
	}

	vrf := &api.VRF{
		IP4: vrf4,
		IP6: vrf6,
	}
	return vrf, nil
}

func getInterfaceVRFChan(ch govppapi.Channel, index uint32) (*api.VRF, error) {
	vrf4, err := getInterfaceTableChan(ch, index, false)
	if err != nil {
		return nil, err
	}
	vrf6, err := getInterfaceTableChan(ch, index, true)
	if err != nil {
		return nil, err
	}

	vrf := &api.VRF{
		IP4: vrf4,
		IP6: vrf6,
	}
	return vrf, nil
}

func getInterfaceIPs(conn govppapi.Connection, index uint32) ([]string, error) {
	ip4, err := dumpIPAddrs(conn, index, false)
	if err != nil {
		return nil, err
	}
	ip6, err := dumpIPAddrs(conn, index, true)
	if err != nil {
		return nil, err
	}

	var ips []string
	ips = append(ips, ip4...)
	ips = append(ips, ip6...)

	return ips, nil
}

func getInterfaceIPsChan(ch govppapi.Channel, index uint32) ([]string, error) {
	ip4, err := dumpIPAddrsChan(ch, index, false)
	if err != nil {
		return nil, err
	}
	ip6, err := dumpIPAddrsChan(ch, index, true)
	if err != nil {
		return nil, err
	}

	var ips []string
	ips = append(ips, ip4...)
	ips = append(ips, ip6...)

	return ips, nil
}

func getInterfaceVRFTable(conn govppapi.Connection, idx uint32, ipv6 bool) (uint, error) {
	rpc := interfaces.NewServiceClient(conn)

	reply, err := rpc.SwInterfaceGetTable(context.Background(), &interfaces.SwInterfaceGetTable{
		SwIfIndex: interface_types.InterfaceIndex(idx),
		IsIPv6:    ipv6,
	})
	if err != nil {
		return 0, err
	} else if e := govppapi.RetvalToVPPApiError(reply.Retval); e != nil {
		return 0, err
	}
	return uint(reply.VrfID), nil
}

func getInterfaceTableChan(ch govppapi.Channel, idx uint32, ipv6 bool) (uint, error) {
	reply := &interfaces.SwInterfaceGetTableReply{}
	err := ch.SendRequest(&interfaces.SwInterfaceGetTable{
		SwIfIndex: interface_types.InterfaceIndex(idx),
		IsIPv6:    ipv6,
	}).ReceiveReply(reply)
	if err != nil {
		return 0, err
	} else if e := govppapi.RetvalToVPPApiError(reply.Retval); e != nil {
		return 0, err
	}
	return uint(reply.VrfID), nil
}

func dumpIPAddrs(conn govppapi.Connection, idx uint32, ipv6 bool) ([]string, error) {
	rpc := ip.NewServiceClient(conn)

	stream, err := rpc.IPAddressDump(context.Background(), &ip.IPAddressDump{
		SwIfIndex: interface_types.InterfaceIndex(idx),
		IsIPv6:    ipv6,
	})
	if err != nil {
		logrus.Error("IPAddressDump failed:", err)
		return nil, err
	}
	var ips []string
	for {
		ipaddr, err := stream.Recv()
		if err == io.EOF {
			break
		} else if err != nil {
			logrus.Error("IPAddressDump failed:", err)
			return nil, err
		}
		ips = append(ips, ipaddr.Prefix.String())
	}
	return ips, nil
}

func dumpIPAddrsChan(ch govppapi.Channel, idx uint32, ipv6 bool) ([]string, error) {
	stream := ch.SendMultiRequest(&ip.IPAddressDump{
		SwIfIndex: interface_types.InterfaceIndex(idx),
		IsIPv6:    ipv6,
	})

	var ips []string
	for {
		ipaddr := &ip.IPAddressDetails{}
		last, err := stream.ReceiveReply(ipaddr)
		if last {
			break
		} else if err != nil {
			return nil, fmt.Errorf("IPAddressDump failed: %v", err)
		}
		ips = append(ips, ipaddr.Prefix.String())
	}
	return ips, nil
}

func dumpApiVersions(ch govppapi.Channel) ([]string, error) {
	reply := &memclnt.APIVersionsReply{}
	err := ch.SendRequest(&memclnt.APIVersions{}).ReceiveReply(reply)
	if err != nil {
		return nil, err
	} else if e := govppapi.RetvalToVPPApiError(reply.Retval); e != nil {
		return nil, err
	}
	var apis []string
	for _, a := range reply.APIVersions {
		apis = append(apis, fmt.Sprintf("%s-%d.%d.%d", a.Name, a.Major, a.Minor, a.Patch))
	}
	return apis, nil
}

func RunCliChan(ch govppapi.Channel, cmd string) (string, error) {
	reply := &vpe.CliInbandReply{}
	err := ch.SendRequest(&vpe.CliInband{Cmd: cmd}).ReceiveReply(reply)
	if err != nil {
		return "", err
	} else if e := govppapi.RetvalToVPPApiError(reply.Retval); e != nil {
		return "", err
	}
	return reply.Reply, nil
}
