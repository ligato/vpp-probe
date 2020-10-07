package vpp

import (
	"context"
	"fmt"
	"io"
	"strings"

	govppapi "git.fd.io/govpp.git/api"
	"github.com/sirupsen/logrus"

	"go.ligato.io/vpp-agent/v3/plugins/vpp/binapi/vpp2001/interface_types"
	"go.ligato.io/vpp-agent/v3/plugins/vpp/binapi/vpp2001/interfaces"
	"go.ligato.io/vpp-agent/v3/plugins/vpp/binapi/vpp2001/ip"
	"go.ligato.io/vpp-agent/v3/plugins/vpp/binapi/vpp2001/vpe"

	"go.ligato.io/vpp-probe/vpp/types"
)

func checkCompatibility(ch govppapi.Channel) error {
	var msgs []govppapi.Message
	msgs = append(msgs, vpe.AllMessages()...)
	msgs = append(msgs, ip.AllMessages()...)
	msgs = append(msgs, interfaces.AllMessages()...)

	if err := ch.CheckCompatiblity(msgs...); err != nil {
		return fmt.Errorf("binapi incompatible: %v", err)
	}

	return nil
}

func getVersion(ch govppapi.Channel) (string, error) {
	rpc := vpe.NewServiceClient(ch)

	reply, err := rpc.ShowVersion(context.Background(), &vpe.ShowVersion{})
	if err != nil {
		return "", err
	}

	return reply.Version, nil
}

func DumpLogs(ch govppapi.Channel) ([]string, error) {
	rpc := vpe.NewServiceClient(ch)

	stream, err := rpc.DumpLog(context.Background(), &vpe.LogDump{
		StartTimestamp: 0,
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
		logLevel := vppLogLevelToString(log.Level)
		logs = append(logs, fmt.Sprintf("[%s] %s: %s", logLevel, log.MsgClass, log.Message))
	}
	return logs, nil
}

func ListInterfaces(ch govppapi.Channel) ([]*types.Interface, error) {
	list, err := dumpInterfaces(ch)
	if err != nil {
		return nil, err
	}
	for _, iface := range list {
		VRFs, err := getInterfaceVRF(ch, iface.Index)
		if err != nil {
			logrus.Errorf("getting interface VRF failed: %v", iface.Index, err)
			return nil, err

		}
		IPs, err := getInterfaceIPs(ch, iface.Index)
		if err != nil {
			logrus.Errorf("getting interface IPs failed: %v", iface.Index, err)
			return nil, err
		}

		iface.IPs = IPs
		iface.VRF = *VRFs
	}
	return list, nil
}

func dumpInterfaces(ch govppapi.Channel) ([]*types.Interface, error) {
	rpc := interfaces.NewServiceClient(ch)

	stream, err := rpc.DumpSwInterface(context.Background(), &interfaces.SwInterfaceDump{})
	if err != nil {
		return nil, fmt.Errorf("DumpSwInterface failed: %v", err)
	}
	var ifaces []*types.Interface
	for {
		iface, err := stream.Recv()
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, fmt.Errorf("DumpSwInterface failed: %v", err)
		}
		ifaces = append(ifaces, &types.Interface{
			Index:      uint32(iface.SwIfIndex),
			Name:       strings.Trim(iface.InterfaceName, "\x00"),
			Tag:        strings.Trim(iface.Tag, "\x00"),
			Type:       vppIfTypeToString(iface.Type),
			DeviceType: iface.InterfaceDevType,
			Status:     vppIfStatusFlagsToStatus(iface.Flags),
			MTUs:       vppInterfaceMTU(iface.Mtu, iface.LinkMtu),
			MAC:        vppL2AddrToString(iface.L2Address),
		})
	}
	return ifaces, nil
}

func getInterfaceVRF(ch govppapi.Channel, index uint32) (*types.VRF, error) {
	vrf4, err := getInterfaceVRFTable(ch, index, false)
	if err != nil {
		return nil, err
	}
	vrf6, err := getInterfaceVRFTable(ch, index, true)
	if err != nil {
		return nil, err
	}

	vrf := &types.VRF{
		IP4: vrf4,
		IP6: vrf6,
	}
	return vrf, nil
}

func getInterfaceIPs(ch govppapi.Channel, index uint32) ([]string, error) {
	var ips []string

	ip4, err := dumpIPAddrs(ch, index, false)
	if err != nil {
		return nil, err
	}
	ips = append(ips, ip4...)

	ip6, err := dumpIPAddrs(ch, index, true)
	if err != nil {
		return nil, err
	}
	ips = append(ips, ip6...)

	return ips, nil
}

func getInterfaceVRFTable(conn govppapi.Channel, idx uint32, ipv6 bool) (uint, error) {
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

func dumpIPAddrs(conn govppapi.Channel, idx uint32, ipv6 bool) ([]string, error) {
	rpc := ip.NewServiceClient(conn)

	stream, err := rpc.DumpIPAddress(context.Background(), &ip.IPAddressDump{
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
		ips = append(ips, vppPrefixToString(ipaddr.Prefix))
	}
	return ips, nil
}
