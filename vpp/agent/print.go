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
		internal := colorTag(color.White, interfaceInternalName(iface))
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
	clr := color.LightMagenta
	ipclr := color.Cyan

	switch iface.Value.Type {
	case vpp_interfaces.Interface_MEMIF:
		memif := iface.Value.GetMemif()
		var info string
		socketParts := strings.Split(memif.GetSocketFilename(), "/")
		for i, part := range socketParts {
			socketParts[i] = colorTag(color.LightBlue, part)
		}
		socket := strings.Join(socketParts, colorTag(color.FgDefault, "/"))
		info += fmt.Sprintf("socket:%s ", socket)
		if memif.Id > 0 {
			info += fmt.Sprintf("id:%v ", colorTag(clr, memif.Id))
		}
		if memif.Master {
			info += fmt.Sprintf("(%s)", colorTag(clr, "master"))
		}
		return info

	case vpp_interfaces.Interface_VXLAN_TUNNEL:
		vxlan := iface.Value.GetVxlan()
		var info string
		info += fmt.Sprintf("%s --> %s (vni:%v)", colorTag(ipclr, vxlan.SrcAddress), colorTag(ipclr, vxlan.DstAddress), colorTag(clr, vxlan.Vni))
		return info

	case vpp_interfaces.Interface_TAP:
		tap := iface.Value.GetTap()
		opt := []string{}
		d := tap.ProtoReflect().Descriptor()
		for i := 0; i < d.Fields().Len(); i++ {
			fd := d.Fields().Get(i)
			if tap.ProtoReflect().Has(fd) {
				f := tap.ProtoReflect().Get(fd)
				if f.IsValid() {
					opt = append(opt, fmt.Sprintf("%s:%s", fd.Name(), colorTag(clr, f.String())))
				}
			}
		}
		return fmt.Sprintf("host_if_name:%s %v", colorTag(clr, iface.Metadata["TAPHostIfName"]), strings.Join(opt, " "))

	case vpp_interfaces.Interface_IPIP_TUNNEL:
		tun := iface.Value.GetIpip()
		var info string
		info += fmt.Sprintf("%s --> %s (mode:%v)", colorTag(ipclr, tun.SrcAddr), colorTag(ipclr, tun.DstAddr), colorTag(clr, tun.TunnelMode))
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
	for i := 0; i < d.Fields().Len(); i++ {
		fd := d.Fields().Get(i)
		if link.Has(fd) {
			f := link.Get(fd)
			if f.IsValid() {
				opt = append(opt, fmt.Sprintf("%s:%s", fd.Name(), colorTag(clr, f.String())))
			}
		}
	}
	return strings.Join(opt, " ")
}
