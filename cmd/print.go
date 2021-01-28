package cmd

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"strings"
	"text/tabwriter"

	"github.com/gookit/color"
	linux_namespace "go.ligato.io/vpp-agent/v3/proto/ligato/linux/namespace"
	vpp_interfaces "go.ligato.io/vpp-agent/v3/proto/ligato/vpp/interfaces"

	"go.ligato.io/vpp-probe/vpp/agent"
)

const (
	tunnelDirectionChar = `🡒`
	defaultPrefix       = "  "
)

var (
	valueColor          = color.New(color.Magenta)
	ipAddressColor      = color.New(color.LightBlue)
	highlightColor      = color.New(color.LightWhite)
	filePathColor       = color.New(color.Cyan)
	interfaceColor      = color.New(color.Yellow)
	statusUpColor       = color.New(color.Green)
	statusDownColor     = color.New(color.Red)
	headerColor         = color.New(color.LightWhite, color.OpBold)
	nonAvailableColor   = color.New(color.FgDarkGray)
	noteColor           = color.New(color.LightBlue)
	instanceHeaderColor = color.New(color.LightYellow, color.OpBold)
)

const (
	defaultVppInterfaceName = "local0"
)

func PrintVPPInterfacesTable(out io.Writer, config *agent.Config) {
	var buf bytes.Buffer
	w := tabwriter.NewWriter(&buf, 0, 8, 1, '\t', tabwriter.StripEscape|tabwriter.FilterHTML|tabwriter.DiscardEmptyColumns)

	header := []string{
		"Idx", "Internal", "Interface", "Type", "State", "IP", " MTU", "Config", "Related",
	}
	for i, h := range header {
		if h != "" {
			header[i] = colorize(color.Bold, h)
		}
	}
	fmt.Fprintln(w, strings.Join(header, "\t"))

	for _, v := range config.VPP.Interfaces {
		if v.Metadata["InternalName"] == defaultVppInterfaceName {
			continue
		}
		iface := v.Value

		idx := fmt.Sprintf("%3v", vppInterfaceIndex(v))
		internal := colorize(highlightColor, interfaceInternalName(v))
		name := colorize(interfaceColor, iface.Name)
		typ := vppInterfaceType(v)
		state := interfaceStatus(v)
		ips := interfaceIPs(iface.IpAddresses, iface.Vrf)
		mtu := interfaceMTU(iface.Mtu)
		info := vppInterfaceInfo(v)
		other := otherInfo(config, v)

		cols := []string{idx, internal, name, typ, state, ips, mtu, info, other}
		fmt.Fprintln(w, strings.Join(cols, "\t"))
	}

	if err := w.Flush(); err != nil {
		log.Println(err)
		return
	}

	fmt.Fprint(out, buf.String())
}

func PrintLinuxInterfacesTable(out io.Writer, config *agent.Config) {
	var buf bytes.Buffer
	w := tabwriter.NewWriter(&buf, 0, 8, 1, '\t', tabwriter.StripEscape|tabwriter.FilterHTML|tabwriter.DiscardEmptyColumns)

	header := []string{
		"Idx", "Internal", "Interface", "Type", "State", "IP", " MTU", "Config", "Namespace",
	}
	for i, h := range header {
		if h != "" {
			header[i] = colorize(color.Bold, h)
		}
	}
	fmt.Fprintln(w, strings.Join(header, "\t"))

	for _, v := range config.Linux.Interfaces {
		iface := v.Value

		idx := fmt.Sprintf("%3v", linuxInterfaceIndex(v))
		internal := colorize(highlightColor, iface.HostIfName)
		name := colorize(interfaceColor, iface.Name)
		typ := linuxInterfaceType(v)
		state := linuxInterfaceStatus(v)
		ips := interfaceIPs(iface.IpAddresses, 0)
		mtu := interfaceMTU(iface.Mtu)
		config := linuxInterfaceInfo(v)
		namespace := linuxIfaceNamespace(iface.Namespace)

		cols := []string{idx, internal, name, typ, state, ips, mtu, config, namespace}
		fmt.Fprintln(w, strings.Join(cols, "\t"))
	}

	if err := w.Flush(); err != nil {
		log.Println(err)
		return
	}

	fmt.Fprint(out, buf.String())
}

func linuxInterfaceType(iface agent.LinuxInterface) string {
	return iface.Value.Type.String()
}

func vppInterfaceType(iface agent.VppInterface) string {
	return iface.Value.Type.String()
}

func linuxIfaceNamespace(namespace *linux_namespace.NetNamespace) string {
	if namespace == nil {
		return "-"
	}
	return fmt.Sprintf("%v: %v", colorize(valueColor, namespace.Type), colorize(color.Cyan, namespace.Reference))
}

func interfaceMTU(mtu uint32) string {
	return fmt.Sprintf("%4d", mtu)
}

func interfaceIPs(ips []string, vrf uint32) string {
	ip := "-"
	if len(ips) > 0 {
		ipsclr := []string{}
		for _, ipaddr := range ips {
			ipsclr = append(ipsclr, colorize(ipAddressColor, ipaddr))
		}
		ip = strings.Join(ipsclr, ", ")
	}
	if vrf > 0 {
		ip += fmt.Sprintf(" (VRF %v)", colorize(color.Cyan, vrf))
	}
	return ip
}

func interfaceInternalName(iface agent.VppInterface) string {
	if name, ok := iface.Metadata["InternalName"]; ok && name != nil {
		return fmt.Sprint(name)
	}
	return ""
}

func vppInterfaceIndex(iface agent.VppInterface) string {
	if idx, ok := iface.Metadata["SwIfIndex"]; ok && idx != nil {
		return fmt.Sprint(idx)
	}
	return ""
}

func linuxInterfaceIndex(iface agent.LinuxInterface) string {
	if idx, ok := iface.Metadata["LinuxIfIndex"]; ok && idx != nil {
		return fmt.Sprint(idx)
	}
	return ""
}

func linuxInterfaceStatus(iface agent.LinuxInterface) string {
	if iface.Value.Enabled {
		return colorize(statusUpColor, "up")
	}
	return colorize(statusDownColor, "down")
}

func interfaceStatus(iface agent.VppInterface) string {
	if iface.Value.Enabled {
		return colorize(statusUpColor, "up")
	}
	return colorize(statusDownColor, "down")
}

func otherInfo(conf *agent.Config, iface agent.VppInterface) string {
	info := []string{}

	// L2 Xconnect
	if xconn := agent.FindL2XconnFor(iface.Value.Name, conf.VPP.L2XConnects); xconn != nil {
		toIface := xconn.Value.ReceiveInterface
		if iface.Value.Name == xconn.Value.ReceiveInterface {
			toIface = xconn.Value.TransmitInterface
		}
		info = append(info, fmt.Sprintf("l2xc to: %v", colorize(interfaceColor, toIface)))
	}

	// IPSec
	if tp := agent.FindIPSecTunProtectFor(iface.Value.Name, conf.VPP.IPSecTunProtects); tp != nil {
		info = append(info, fmt.Sprintf("ipsec-sa in:%v out:%v", colorize(color.Cyan, tp.Value.SaIn), colorize(color.Cyan, tp.Value.SaOut)))
	}

	// Routes
	/*for _, r := range agent.FindVppRoutesFor(iface.Value.Name, conf.VPP.Routes) {
		if r.Origin != api.FromNB {
			continue
		}
		info = append(info, fmt.Sprintf("route:%v", colorize(color.Cyan, r.Value.DstNetwork)))
	}*/

	return strings.Join(info, ", ")
}

func vppInterfaceInfo(iface agent.VppInterface) string {

	switch iface.Value.Type {
	case vpp_interfaces.Interface_MEMIF:
		memif := iface.Value.GetMemif()
		var info string
		socketParts := strings.Split(memif.GetSocketFilename(), "/")
		for i, part := range socketParts {
			socketParts[i] = colorize(filePathColor, part)
		}
		socket := strings.Join(socketParts, colorize(color.OpReset, "/"))
		info += fmt.Sprintf("socket:%s ", socket)
		if memif.Id > 0 {
			info += fmt.Sprintf("id:%v ", colorize(valueColor, memif.Id))
		}
		if memif.Master {
			info += fmt.Sprintf("(%s)", colorize(valueColor, "master"))
		}
		return info

	case vpp_interfaces.Interface_VXLAN_TUNNEL:
		vxlan := iface.Value.GetVxlan()
		var info string
		info += fmt.Sprintf("%s %s %s (vni:%v)", colorize(ipAddressColor, vxlan.SrcAddress), tunnelDirectionChar, colorize(ipAddressColor, vxlan.DstAddress), colorize(valueColor, vxlan.Vni))
		return info

	case vpp_interfaces.Interface_TAP:
		tap := iface.Value.GetTap()
		pr := tap.ProtoReflect()
		m := protoFieldsToMap(pr.Descriptor().Fields(), pr)
		fieldsStr := mapKeyValString(m, func(k string, v string) string {
			return fmt.Sprintf("%s:%s", k, colorize(valueColor, v))
		})
		return fmt.Sprintf("host_if_name:%s %v", colorize(valueColor, iface.Metadata["TAPHostIfName"]), fieldsStr)

	case vpp_interfaces.Interface_IPIP_TUNNEL:
		tun := iface.Value.GetIpip()
		var info string
		info += fmt.Sprintf("%s %s %s mode:%v", colorize(ipAddressColor, tun.SrcAddr), tunnelDirectionChar, colorize(ipAddressColor, tun.DstAddr), colorize(valueColor, tun.TunnelMode))
		return info
	}

	ref := iface.Value.ProtoReflect()
	ld := ref.Descriptor().Oneofs().ByName("link")
	wd := ref.WhichOneof(ld)
	if wd == nil {
		return ""
	}
	d := wd.Message()
	link := ref.Get(wd).Message()

	m := protoFieldsToMap(d.Fields(), link)
	return mapKeyValString(m, func(k string, v string) string {
		return fmt.Sprintf("%s:%s", k, colorize(valueColor, v))
	})
}

func linuxInterfaceInfo(iface agent.LinuxInterface) string {
	ref := iface.Value.ProtoReflect()
	ld := ref.Descriptor().Oneofs().ByName("link")
	wd := ref.WhichOneof(ld)
	if wd == nil {
		return ""
	}
	d := wd.Message()
	link := ref.Get(wd).Message()

	m := protoFieldsToMap(d.Fields(), link)
	return mapKeyValString(m, func(k string, v string) string {
		return fmt.Sprintf("%s:%s", k, colorize(valueColor, v))
	})
}
