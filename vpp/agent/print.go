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
	fmt.Fprintln(out, "----------")
	fmt.Fprintf(out, "= Instance: %+v\n", instance.Metadata)
	fmt.Fprintln(out, "----------")

	fmt.Fprintf(out, " Version: %s\n", color.FgLightBlue.Sprint(instance.Version))
	fmt.Fprintln(out)

	PrintInterfacesTable(out, instance)
	fmt.Fprintln(out)
	fmt.Fprintf(out, "%d vpp interfaces\n", len(instance.VppInterfaces))

	if len(instance.LinuxInterfaces) > 0 {
		fmt.Fprintln(out)
		fmt.Fprintf(out, "%d linux interfaces:\n", len(instance.LinuxInterfaces))
		for _, v := range instance.LinuxInterfaces {
			fmt.Printf(" - %v:\n", v.Value)
		}
	}
	fmt.Fprintf(out, "\n")
}

func PrintCLIs(out io.Writer, instance *Instance) {
	for k, v := range instance.Extra {
		val := color.FgLightBlue.Sprint(v)
		val = "\t" + strings.ReplaceAll(val, "\n", "\n\t")
		fmt.Fprintf(out, "%s:\n\n%s\n", k, val)
		fmt.Fprintln(out)
	}
	fmt.Fprintln(out)
}

func PrintInterfacesTable(out io.Writer, instance *Instance) {
	ifaces := instance.VppInterfaces
	xconns := instance.L2XConnects
	tunprots := instance.IPSecTunProtects

	var buf bytes.Buffer
	w := tabwriter.NewWriter(&buf, 1, 8, 0, '\t', tabwriter.StripEscape)
	fmt.Fprintf(w, "IDX\t%v\t%v\t%v\t%v\tVRF\t%s\tDETAILS\t\n",
		escapeClr(color.LightWhite, "INTERFACE"), escapeClr(color.White, "TYPE"), escapeClr(color.White, "STATE"), escapeClr(color.White, "IP"), escapeClr(color.White, "MTU"))
	for _, iface := range ifaces {
		name := escapeClr(color.LightWhite, iface.Value.Name)
		state := escapeClr(color.Red, "down")
		if iface.Value.Enabled {
			state = escapeClr(color.Green, "up")
		}
		idx := iface.Metadata["SwIfIndex"]
		typ := escapeClr(color.LightMagenta, iface.Value.Type)
		ips := escapeClr(color.LightBlue, strings.Join(iface.Value.IpAddresses, " "))
		vrf := iface.Value.Vrf
		mtu := escapeClr(color.Yellow, iface.Value.Mtu)
		endOfLine := "\n"
		if xconn := FindL2XconnFor(iface.Value.Name, xconns); xconn != nil {
			if iface.Value.Name == xconn.Value.ReceiveInterface {
				endOfLine = fmt.Sprintf("(l2xc to %s)\n", xconn.Value.TransmitInterface)
			} else {
				endOfLine = fmt.Sprintf("(l2xc to %s)\n", xconn.Value.ReceiveInterface)
			}
		}
		if tp := FindIPSecTunProtectFor(iface.Value.Name, tunprots); tp != nil {
			endOfLine = fmt.Sprintf("(IPSec SA in:%v / out:%v)\n", tp.Value.SaIn, tp.Value.SaOut)
		}
		fmt.Fprintf(w, "%3v\t%v\t%v\t%v\v%v\t%v\t%v\t%v %s",
			idx, name, typ, state, ips, vrf, mtu, interfaceInfo(iface), endOfLine)
	}
	if err := w.Flush(); err != nil {
		log.Println(err)
		return
	}
	fmt.Fprint(out, buf.String())
}

func interfaceInfo(iface VppInterface) string {
	switch iface.Value.Type {
	case vpp_interfaces.Interface_MEMIF:
		memif := iface.Value.GetMemif()
		var info string
		info += fmt.Sprintf("socket:%s ", escapeClr(color.LightYellow, memif.SocketFilename))
		if memif.Id > 0 {
			info += fmt.Sprintf("ID:%d ", memif.Id)
		}
		if memif.Master {
			info += fmt.Sprintf("master:%s ", escapeClr(color.LightYellow, memif.Master))
		}
		return info

	case vpp_interfaces.Interface_VXLAN_TUNNEL:
		vxlan := iface.Value.GetVxlan()
		var info string
		info += fmt.Sprintf("src:%s -> dst:%s (vni:%v)", escapeClr(color.LightYellow, vxlan.SrcAddress), escapeClr(color.LightYellow, vxlan.DstAddress), escapeClr(color.LightYellow, vxlan.Vni))
		return info

	case vpp_interfaces.Interface_TAP:
		tap := iface.Value.GetTap()
		return fmt.Sprintf("host_ifname:%s %v", escapeClr(color.LightYellow, iface.Metadata["TAPHostIfName"]), tap.String())

	case vpp_interfaces.Interface_AF_PACKET:
		afp := iface.Value.GetAfpacket()
		var info string
		info += fmt.Sprintf("host_if_name:%s", escapeClr(color.LightYellow, afp.HostIfName))
		return info

	case vpp_interfaces.Interface_IPIP_TUNNEL:
		tun := iface.Value.GetIpip()
		var info string
		info += fmt.Sprintf("src:%s -> dst:%s (mode:%v)", escapeClr(color.LightYellow, tun.SrcAddr), escapeClr(color.LightYellow, tun.DstAddr), escapeClr(color.LightYellow, tun.TunnelMode))
		return info
	}
	return fmt.Sprint(iface.Value.GetLink())
}
