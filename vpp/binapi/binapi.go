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

	"go.ligato.io/vpp-agent/v3/plugins/vpp/binapi/vpp2001/interface_types"
	"go.ligato.io/vpp-agent/v3/plugins/vpp/binapi/vpp2001/interfaces"
	"go.ligato.io/vpp-agent/v3/plugins/vpp/binapi/vpp2001/ip"
	"go.ligato.io/vpp-agent/v3/plugins/vpp/binapi/vpp2001/vpe"

	_ "go.ligato.io/vpp-agent/v3/plugins/vpp/binapi/vpp2001"
	_ "go.ligato.io/vpp-agent/v3/plugins/vpp/binapi/vpp2005"
	_ "go.ligato.io/vpp-agent/v3/plugins/vpp/binapi/vpp2009"

	_ "go.ligato.io/vpp-agent/v3/plugins/govppmux/vppcalls/vpp2001"
	_ "go.ligato.io/vpp-agent/v3/plugins/govppmux/vppcalls/vpp2005"
	_ "go.ligato.io/vpp-agent/v3/plugins/govppmux/vppcalls/vpp2009"

	"go.ligato.io/vpp-probe/vpp/api"
)

/*func init() {
	ver := binapi.Versions[vpp2001.Version]
	var core = binapi.MessagesList{}
	for _, allmsg := range ver.Core {
		msgs := allmsg()
		skip := false
		for _, msg := range msgs {
			if strings.HasPrefix(msg.GetMessageName(), "ipfix") ||
				strings.HasPrefix(msg.GetMessageName(), "flowprobe") {
				skip = true
				break
			}
		}
		if skip {
			continue
		}
		core.Add(allmsg)
	}
	binapi.Versions[vpp2001.Version] = binapi.VersionMsgs{
		Core:    core,
		Plugins: ver.Plugins,
	}
}*/

//const vppVersion = vpp2001.Version

func checkCompatibility(ch govppapi.Channel) error {

	/*versionMsgs := binapi.Versions[version]

	  // All binapi messages must be registered to gob
	  for _, msg := range versionMsgs.AllMessages() {
	  	gob.Register(msg)
	  }*/

	/*var msgs []govppapi.Message
	  msgs = append(msgs, vpe.AllMessages()...)
	  msgs = append(msgs, ip.AllMessages()...)
	  msgs = append(msgs, interfaces.AllMessages()...)*/

	/*msgs := versionMsgs.Core.AllMessages()

	  if err := ch.CheckCompatiblity(msgs...); err != nil {
	  	logrus.Warnf("compatibility check failed: %v", err)
	  	return fmt.Errorf("incompatible")
	  }*/

	return nil
}

func GetVersionInfo(ch govppapi.Channel) (*api.VersionInfo, error) {
	version, err := GetVersion(ch)
	if err != nil {
		return nil, err
	}
	pid, err := GetPID(ch)
	if err != nil {
		return nil, err
	}
	return &api.VersionInfo{
		Version: version,
		Pid:     pid,
	}, nil
}

func GetPID(ch govppapi.Channel) (int, error) {
	rpc := vpe.NewServiceClient(ch)

	reply, err := rpc.ControlPing(context.Background(), &vpe.ControlPing{})
	if err != nil {
		return 0, err
	}

	return int(reply.VpePID), nil
}

func GetVersion(ch govppapi.Channel) (string, error) {
	rpc := vpe.NewServiceClient(ch)

	reply, err := rpc.ShowVersion(context.Background(), &vpe.ShowVersion{})
	if err != nil {
		return "", err
	}

	return reply.Version, nil
}

func GetSystemTime(ch govppapi.Channel) (time.Duration, error) {
	rpc := vpe.NewServiceClient(ch)

	reply, err := rpc.ShowVpeSystemTime(context.Background(), &vpe.ShowVpeSystemTime{})
	if err != nil {
		return 0, err
	}

	sysTime := math.Float64bits(float64(reply.VpeSystemTime))
	uptime := time.Duration(sysTime) * time.Second

	return uptime, nil
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
		logs = append(logs, formatLogLine(log))
	}
	return logs, nil
}

func DumpLogsSince(ch govppapi.Channel, t time.Time) ([]string, error) {
	rpc := vpe.NewServiceClient(ch)

	stream, err := rpc.DumpLog(context.Background(), &vpe.LogDump{
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

func ListInterfaces(ch govppapi.Channel) ([]*api.Interface, error) {
	list, err := dumpInterfaces(ch)
	if err != nil {
		return nil, err
	}
	for _, iface := range list {
		VRFs, err := getInterfaceVRF(ch, iface.Index)
		if err != nil {
			logrus.Errorf("getting interface %d VRF failed: %v", iface.Index, err)
			return nil, err

		}
		IPs, err := getInterfaceIPs(ch, iface.Index)
		if err != nil {
			logrus.Errorf("getting interface %d IPs failed: %v", iface.Index, err)
			return nil, err
		}

		iface.IPs = IPs
		iface.VRF = *VRFs
	}
	return list, nil
}

func dumpInterfaces(ch govppapi.Channel) ([]*api.Interface, error) {
	rpc := interfaces.NewServiceClient(ch)

	stream, err := rpc.DumpSwInterface(context.Background(), &interfaces.SwInterfaceDump{})
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
			MAC:        vppL2AddrToString(iface.L2Address),
		})
	}
	return ifaces, nil
}

func getInterfaceVRF(ch govppapi.Channel, index uint32) (*api.VRF, error) {
	vrf4, err := getInterfaceVRFTable(ch, index, false)
	if err != nil {
		return nil, err
	}
	vrf6, err := getInterfaceVRFTable(ch, index, true)
	if err != nil {
		return nil, err
	}

	vrf := &api.VRF{
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
