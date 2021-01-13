package agent

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"strings"
	"text/tabwriter"

	"github.com/gookit/color"
	vpp_interfaces "go.ligato.io/vpp-agent/v3/proto/ligato/vpp/interfaces"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func PrintInstance(out io.Writer, instance *Instance) {
	var buf bytes.Buffer

	// info
	fmt.Fprintf(&buf, "VPP version: %s\n", color.FgLightBlue.Sprint(instance.Version))
	fmt.Fprintln(&buf)

	// interfaces
	PrintInterfacesTable(&buf, instance.Config)

	if len(instance.Config.Linux.Interfaces) > 0 {
		fmt.Fprintln(&buf)
		for _, v := range instance.Config.Linux.Interfaces {
			fmt.Fprintf(&buf, " - %v\n", v.Value)
		}
	}
	fmt.Fprintf(&buf, "\n")

	fmt.Fprintln(out, prefixString(buf.String(), "  "))
}

func PrintCLIs(out io.Writer, instance *Instance) {
	for k, v := range instance.CliData {
		val := color.FgLightBlue.Sprint(v)
		val = "\t" + strings.ReplaceAll(val, "\n", "\n\t")
		fmt.Fprintf(out, "%s:\n\n%s\n", k, val)
		fmt.Fprintln(out)
	}
	fmt.Fprintln(out)
}

const defaultVppInterfaceName = "local0"

func PrintInterfacesTable(out io.Writer, config *Config) {
	var buf bytes.Buffer
	w := tabwriter.NewWriter(&buf, 0, 8, 1, '\t', tabwriter.StripEscape|tabwriter.FilterHTML|tabwriter.DiscardEmptyColumns)

	// header
	header := []string{
		"Idx", "Internal", "Interface", "Type", "State", "IP", "MTU", "Config", "Attached",
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

		idx := fmt.Sprintf("%3v", interfaceIndex(iface))
		internal := interfaceInternalName(iface)
		name := colorTag(color.Yellow, iface.Value.Name)
		typ := colorTag(color.Magenta, iface.Value.Type)
		state := interfaceStatus(iface)
		ips := interfaceIPs(iface)
		mtu := interfaceMTU(iface)
		info := interfaceInfo(iface)
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

func interfaceMTU(iface VppInterface) string {
	mtu := "0"
	if iface.Value.Mtu > 0 {
		mtu = fmt.Sprint(iface.Value.Mtu)
	}
	return mtu
}

func interfaceIPs(iface VppInterface) string {
	ip := "-"
	if len(iface.Value.IpAddresses) > 0 {
		ips := []string{}
		for _, ipaddr := range iface.Value.IpAddresses {
			ips = append(ips, colorTag(color.Blue, ipaddr))
		}
		ip = strings.Join(ips, ", ")
	}
	if iface.Value.Vrf > 0 {
		ip += fmt.Sprintf(" (VRF %v)", colorTag(color.Cyan, iface.Value.Vrf))
	}
	return ip
}

func interfaceInternalName(iface VppInterface) string {
	if name, ok := iface.Metadata["InternalName"]; ok && name != nil {
		return fmt.Sprint(name)
	}
	return "?"
}

func interfaceIndex(iface VppInterface) string {
	if idx, ok := iface.Metadata["SwIfIndex"]; ok && idx != nil {
		return fmt.Sprint(idx)
	}
	return "?"
}

func interfaceStatus(iface VppInterface) string {
	if iface.Value.Enabled {
		return colorTag(color.Green, "up")
	} else {
		return colorTag(color.Red, "down")
	}
}

func otherInfo(conf *Config, iface VppInterface) string {
	info := []string{}

	// L2 Xconnect
	if xconn := FindL2XconnFor(iface.Value.Name, conf.VPP.L2XConnects); xconn != nil {
		toIface := xconn.Value.ReceiveInterface
		if iface.Value.Name == xconn.Value.ReceiveInterface {
			toIface = xconn.Value.TransmitInterface
		}
		info = append(info, fmt.Sprintf("l2xc to %v", colorTag(color.Yellow, toIface)))
	}

	// IPSec
	if tp := FindIPSecTunProtectFor(iface.Value.Name, conf.VPP.IPSecTunProtects); tp != nil {
		info = append(info, fmt.Sprintf("ipsec-sa in:%v out:%v", colorTag(color.Cyan, tp.Value.SaIn), colorTag(color.Cyan, tp.Value.SaOut)))
	}

	return strings.Join(info, ", ")
}

func interfaceInfo(iface VppInterface) string {
	const (
		valueColor = color.LightMagenta
		ipColor    = color.Blue
		pathColor  = color.Cyan
		tunnelDir  = `🡒`
	)

	switch iface.Value.Type {
	case vpp_interfaces.Interface_MEMIF:
		memif := iface.Value.GetMemif()
		var info string
		socketParts := strings.Split(memif.GetSocketFilename(), "/")
		for i, part := range socketParts {
			socketParts[i] = colorTag(pathColor, part)
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
		info += fmt.Sprintf("%s %s %s (vni:%v)", colorTag(ipColor, vxlan.SrcAddress), tunnelDir, colorTag(ipColor, vxlan.DstAddress), colorTag(valueColor, vxlan.Vni))
		return info

	case vpp_interfaces.Interface_TAP:
		tap := iface.Value.GetTap()
		opt := []string{}
		pr := tap.ProtoReflect()
		m := protoFieldsToMap(pr.Descriptor().Fields(), pr)
		for k, v := range m {
			opt = append(opt, fmt.Sprintf("%s:%s", k, colorTag(valueColor, v)))
		}
		return fmt.Sprintf("host_if_name:%s %v", colorTag(valueColor, iface.Metadata["TAPHostIfName"]), strings.Join(opt, " "))

	case vpp_interfaces.Interface_IPIP_TUNNEL:
		tun := iface.Value.GetIpip()
		var info string
		info += fmt.Sprintf("%s %s %s mode:%v", colorTag(ipColor, tun.SrcAddr), tunnelDir, colorTag(ipColor, tun.DstAddr), colorTag(valueColor, tun.TunnelMode))
		return info
	}

	ref := iface.Value.ProtoReflect()
	ld := ref.Descriptor().Oneofs().ByName("link")
	opt := []string{}
	wd := ref.WhichOneof(ld)
	if wd == nil {
		return ""
	}
	d := wd.Message()
	link := ref.Get(wd).Message()
	m := protoFieldsToMap(d.Fields(), link)
	for k, v := range m {
		opt = append(opt, fmt.Sprintf("%s:%s", k, colorTag(valueColor, v)))
	}
	return strings.Join(opt, " ")
}

func protoFieldsToMap(fields protoreflect.FieldDescriptors, pb protoreflect.Message) map[string]string {
	m := map[string]string{}
	for i := 0; i < fields.Len(); i++ {
		fd := fields.Get(i)
		if pb.Has(fd) {
			f := pb.Get(fd)
			if f.IsValid() {
				m[string(fd.Name())] = f.String()
			}
		}
	}
	return m
}
