package cmd

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"strings"
	"text/tabwriter"

	"github.com/gookit/color"
	"github.com/sirupsen/logrus"
	linux_namespace "go.ligato.io/vpp-agent/v3/proto/ligato/linux/namespace"
	vpp_interfaces "go.ligato.io/vpp-agent/v3/proto/ligato/vpp/interfaces"

	"go.ligato.io/vpp-probe/vpp/agent"
)

const (
	valueColor          = color.LightMagenta
	ipAddressColor      = color.Blue
	filePathColor       = color.Cyan
	interfaceColor      = color.Yellow
	statusUpColor       = color.Green
	statusDownColor     = color.Red
	tunnelDirectionChar = `🡒`
	defaultPrefix       = "  "
)

var (
	headerColor       = color.New(color.FgLightWhite, color.OpBold)
	nonAvailableColor = color.New(color.FgDarkGray)
	noteColor         = color.New(color.FgLightBlue)
)

func PrintInstance(out io.Writer, instance *agent.Instance) {
	var buf bytes.Buffer

	// info
	{
		fmt.Fprintf(&buf, "VPP version: %s\n", noteColor.Sprint(instance.Version))
	}
	fmt.Fprintln(&buf)

	// VPP interfaces
	fmt.Fprintln(&buf, headerColor.Sprint("VPP interfaces"))
	{
		w := prefixWriter(&buf, defaultPrefix)
		if len(instance.Config.VPP.Interfaces) > 0 {
			PrintVPPInterfacesTable(w, instance.Config)
		} else {
			fmt.Fprintln(w, nonAvailableColor.Sprint("No interfaces configured"))
		}
	}
	fmt.Fprintln(&buf)

	// Linux interfaces
	fmt.Fprintln(&buf, headerColor.Sprint("Linux interfaces"))
	{
		w := prefixWriter(&buf, defaultPrefix)
		if len(instance.Config.Linux.Interfaces) > 0 {
			PrintLinuxInterfacesTable(w, instance.Config)
		} else {
			fmt.Fprintln(w, nonAvailableColor.Sprint("No interfaces configured"))
		}
	}
	fmt.Fprintln(&buf)

	if _, err := buf.WriteTo(out); err != nil {
		logrus.Warnf("writing to output failed: %v", err)
	}
}

const (
	defaultVppInterfaceName = "local0"
)

func PrintVPPInterfacesTable(out io.Writer, config *agent.Config) {
	var buf bytes.Buffer
	w := tabwriter.NewWriter(&buf, 0, 8, 1, '\t', tabwriter.StripEscape|tabwriter.FilterHTML|tabwriter.DiscardEmptyColumns)

	// header
	header := []string{
		"Idx", "Internal", "Interface", "Type", "State", "IP", " MTU", "Config", "Related",
	}
	for i, h := range header {
		if h != "" {
			header[i] = colorTag(color.Bold, h)
		}
	}
	fmt.Fprintln(w, strings.Join(header, "\t"))

	// interfaces
	for _, iface := range config.VPP.Interfaces {
		if iface.Metadata["InternalName"] == defaultVppInterfaceName {
			continue
		}

		idx := fmt.Sprintf("%3v", vppInterfaceIndex(iface))
		internal := interfaceInternalName(iface)
		name := colorTag(interfaceColor, iface.Value.Name)
		typ := colorTag(color.Magenta, iface.Value.Type)
		state := interfaceStatus(iface)
		ips := interfaceIPs(iface.Value.IpAddresses, iface.Value.Vrf)
		mtu := interfaceMTU(iface.Value.Mtu)
		info := vppInterfaceInfo(iface)
		other := otherInfo(config, iface)

		cols := []string{idx, internal, name, typ, state, ips, mtu, info, other}
		fmt.Fprintln(w, strings.Join(cols, "\t"))
	}

	if err := w.Flush(); err != nil {
		log.Println(err)
		return
	}

	fmt.Fprint(out, color.ReplaceTag(buf.String()))
}

func PrintLinuxInterfacesTable(out io.Writer, config *agent.Config) {
	var buf bytes.Buffer
	w := tabwriter.NewWriter(&buf, 0, 8, 1, '\t', tabwriter.StripEscape|tabwriter.FilterHTML|tabwriter.DiscardEmptyColumns)

	// header
	header := []string{
		"Idx", "Internal", "Interface", "Type", "State", "IP", " MTU", "Config", "Namespace",
	}
	for i, h := range header {
		if h != "" {
			header[i] = colorTag(color.Bold, h)
		}
	}
	fmt.Fprintln(w, strings.Join(header, "\t"))

	for _, v := range config.Linux.Interfaces {
		iface := v.Value

		idx := fmt.Sprintf("%3v", linuxInterfaceIndex(v))
		internal := iface.HostIfName
		name := colorTag(interfaceColor, iface.Name)
		typ := colorTag(color.Magenta, v.Value.Type)
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

	fmt.Fprint(out, color.ReplaceTag(buf.String()))
}

func linuxIfaceNamespace(namespace *linux_namespace.NetNamespace) string {
	if namespace == nil {
		return "-"
	}
	return fmt.Sprintf("%v: %v", colorTag(valueColor, namespace.Type), colorTag(color.Cyan, namespace.Reference))
}

func interfaceMTU(mtu uint32) string {
	return fmt.Sprintf("%4d", mtu)
}

func interfaceIPs(ips []string, vrf uint32) string {
	ip := "-"
	if len(ips) > 0 {
		ipsclr := []string{}
		for _, ipaddr := range ips {
			ipsclr = append(ipsclr, colorTag(ipAddressColor, ipaddr))
		}
		ip = strings.Join(ipsclr, ", ")
	}
	if vrf > 0 {
		ip += fmt.Sprintf(" (VRF %v)", colorTag(color.Cyan, vrf))
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
		return colorTag(statusUpColor, "up")
	}
	return colorTag(statusDownColor, "down")
}

func interfaceStatus(iface agent.VppInterface) string {
	if iface.Value.Enabled {
		return colorTag(statusUpColor, "up")
	}
	return colorTag(statusDownColor, "down")
}

func otherInfo(conf *agent.Config, iface agent.VppInterface) string {
	info := []string{}

	// L2 Xconnect
	if xconn := agent.FindL2XconnFor(iface.Value.Name, conf.VPP.L2XConnects); xconn != nil {
		toIface := xconn.Value.ReceiveInterface
		if iface.Value.Name == xconn.Value.ReceiveInterface {
			toIface = xconn.Value.TransmitInterface
		}
		info = append(info, fmt.Sprintf("l2xc to %v", colorTag(interfaceColor, toIface)))
	}

	// IPSec
	if tp := agent.FindIPSecTunProtectFor(iface.Value.Name, conf.VPP.IPSecTunProtects); tp != nil {
		info = append(info, fmt.Sprintf("ipsec-sa in:%v out:%v", colorTag(color.Cyan, tp.Value.SaIn), colorTag(color.Cyan, tp.Value.SaOut)))
	}

	return strings.Join(info, ", ")
}

func vppInterfaceInfo(iface agent.VppInterface) string {

	switch iface.Value.Type {
	case vpp_interfaces.Interface_MEMIF:
		memif := iface.Value.GetMemif()
		var info string
		socketParts := strings.Split(memif.GetSocketFilename(), "/")
		for i, part := range socketParts {
			socketParts[i] = colorTag(filePathColor, part)
		}
		socket := strings.Join(socketParts, colorTag(color.OpReset, "/"))
		info += fmt.Sprintf("socket:%s ", socket)
		if memif.Id > 0 {
			info += fmt.Sprintf("id:%v ", colorTag(valueColor, memif.Id))
		}
		if memif.Master {
			info += fmt.Sprintf("(%s)", colorTag(valueColor, "master"))
		}
		return info

	case vpp_interfaces.Interface_VXLAN_TUNNEL:
		vxlan := iface.Value.GetVxlan()
		var info string
		info += fmt.Sprintf("%s %s %s (vni:%v)", colorTag(ipAddressColor, vxlan.SrcAddress), tunnelDirectionChar, colorTag(ipAddressColor, vxlan.DstAddress), colorTag(valueColor, vxlan.Vni))
		return info

	case vpp_interfaces.Interface_TAP:
		tap := iface.Value.GetTap()
		pr := tap.ProtoReflect()
		m := protoFieldsToMap(pr.Descriptor().Fields(), pr)
		fieldsStr := mapKeyValString(m, func(k string, v string) string {
			return fmt.Sprintf("%s:%s", k, colorTag(valueColor, v))
		})
		return fmt.Sprintf("host_if_name:%s %v", colorTag(valueColor, iface.Metadata["TAPHostIfName"]), fieldsStr)

	case vpp_interfaces.Interface_IPIP_TUNNEL:
		tun := iface.Value.GetIpip()
		var info string
		info += fmt.Sprintf("%s %s %s mode:%v", colorTag(ipAddressColor, tun.SrcAddr), tunnelDirectionChar, colorTag(ipAddressColor, tun.DstAddr), colorTag(valueColor, tun.TunnelMode))
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
		return fmt.Sprintf("%s:%s", k, colorTag(valueColor, v))
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
		return fmt.Sprintf("%s:%s", k, colorTag(valueColor, v))
	})
}
