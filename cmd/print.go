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
	"google.golang.org/protobuf/reflect/protoreflect"

	"go.ligato.io/vpp-probe/vpp"

	"go.ligato.io/vpp-probe/probe"
	"go.ligato.io/vpp-probe/providers"
	"go.ligato.io/vpp-probe/vpp/agent"
)

const (
	tunnelDirectionChar = `->`
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

func renderColor(s string) string {
	if !color.Enable {
		s = color.ClearCode(s)
		return color.ClearTag(s)
	}
	str := color.ReplaceTag(s)
	return str
}

func printInstanceHeader(out io.Writer, handler probe.Handler) {
	metadata := handler.Metadata()

	metaKey := func(k string) string {
		v := metadata[k]
		return fmt.Sprintf("%s: %v", k, colorize(instanceHeaderColor, v))
	}

	var header []string

	switch metadata["env"] {
	case providers.Kube:
		header = []string{
			metaKey("pod"),
			metaKey("namespace"),
			metaKey("node"),
			metaKey("cluster"),
			metaKey("ip"),
		}
	case providers.Docker:
		header = []string{
			metaKey("container"),
			metaKey("image"),
			metaKey("id"),
		}
	case providers.Local:
		header = []string{
			metaKey("pid"),
			metaKey("id"),
		}
	default:
		for k := range metadata {
			header = append(header, metaKey(k))
		}
	}

	fmt.Fprintln(out, "----------------------------------------------------------------------------------------------------------------------------------")
	fmt.Fprintf(out, " %s\n", strings.Join(header, " | "))
	fmt.Fprintln(out, "----------------------------------------------------------------------------------------------------------------------------------")
}

func printSectionHeader(out io.Writer, header []string) {
	fmt.Fprintln(out, "----------------------------------------------------------------------------------------------------------------------------------")
	fmt.Fprintf(out, " %s\n", strings.Join(header, " | "))
	fmt.Fprintln(out, "----------------------------------------------------------------------------------------------------------------------------------")
}

const (
	defaultVppInterfaceName = "local0"
)

func PrintVPPInterfacesTable(out io.Writer, instance *vpp.Instance) {
	var buf bytes.Buffer
	w := tabwriter.NewWriter(&buf, 0, 1, 2, ' ', tabwriter.StripEscape|tabwriter.FilterHTML|tabwriter.DiscardEmptyColumns)

	header := []string{
		"Idx", "Internal", "Interface", "Type", "State", "IP", "MTU", "MAC", "Config", "Related", "Stats",
	}
	for i, h := range header {
		if h != "" {
			header[i] = colorize(color.Bold, h)
		}
	}
	fmt.Fprintln(w, strings.Join(header, "\t"))

	config := instance.Agent().Config

	for _, v := range config.VPP.Interfaces {
		if v.Metadata["InternalName"] == defaultVppInterfaceName {
			continue
		}
		iface := v.Value

		idx := fmt.Sprintf("%3v", vppInterfaceIndex(v))
		internal := colorize(highlightColor, interfaceInternalName(v))
		name := colorize(interfaceColor, iface.Name)
		typ := vppInterfaceType(v)
		state := vppInterfaceStatus(v, config.VPP.Interfaces)
		ips := vppInterfaceIPs(iface)
		mtu := interfaceMTU(iface.Mtu)
		mac := interfaceMAC(iface.PhysAddress)
		info := vppInterfaceInfo(v)
		other := relatedInfo(config, v)
		stats := vppInterfaceStats(instance, v)

		cols := []string{
			idx, internal, name, typ, state, ips, mtu, mac, info, other, stats,
		}
		fmt.Fprintln(w, strings.Join(cols, "\t"))
	}

	if err := w.Flush(); err != nil {
		log.Println(err)
		return
	}

	fmt.Fprint(out, buf.String())
}

func interfaceMAC(address string) string {
	if address == "00:00:00:00:00:00" {
		return "-"
	}
	return address
}

func PrintLinuxInterfacesTable(out io.Writer, instance *vpp.Instance) {
	var buf bytes.Buffer
	w := tabwriter.NewWriter(&buf, 0, 1, 2, ' ', tabwriter.StripEscape|tabwriter.FilterHTML|tabwriter.DiscardEmptyColumns)

	header := []string{
		"Idx", "Internal", "Interface", "Type", "State", "IP", "MTU", "MAC", "Config", "Namespace",
	}
	for i, h := range header {
		if h != "" {
			header[i] = colorize(color.Bold, h)
		}
	}
	fmt.Fprintln(w, strings.Join(header, "\t"))

	config := instance.Agent().Config

	for _, v := range config.Linux.Interfaces {
		iface := v.Value

		idx := fmt.Sprintf("%3v", linuxInterfaceIndex(v))
		internal := colorize(highlightColor, iface.HostIfName)
		name := colorize(interfaceColor, iface.Name)
		typ := linuxInterfaceType(v)
		state := linuxInterfaceStatus(v)
		ips := interfaceIPs(iface.IpAddresses, 0)
		mtu := interfaceMTU(iface.Mtu)
		mac := interfaceMAC(iface.PhysAddress)
		config := interfaceLinkInfo(v.Value.ProtoReflect()) //linuxInterfaceInfo(v)
		namespace := linuxIfaceNamespace(iface.Namespace)

		cols := []string{idx, internal, name, typ, state, ips, mtu, mac, config, namespace}
		fmt.Fprintln(w, strings.Join(cols, "\t"))
	}

	if err := w.Flush(); err != nil {
		log.Println(err)
		return
	}

	fmt.Fprint(out, buf.String())
}

func PrintCorrelatedIpSec(out io.Writer, correlations *agent.IPSecCorrelations) {
	var buf bytes.Buffer
	w := tabwriter.NewWriter(&buf, 0, 8, 1, '\t', tabwriter.StripEscape|tabwriter.FilterHTML|tabwriter.DiscardEmptyColumns)

	header := []string{
		"IP in <-> out", "Peer?", "SA", "SA-match?", "SPI", "CRYPTO", "INTEG", "MatchFlags",
	}
	for i, h := range header {
		if h != "" {
			header[i] = colorize(color.Bold, h)
		}
	}
	fmt.Fprintln(w, strings.Join(header, "\t"))

	// correlate data
	for inSrcIp, inSpMap := range correlations.InSpSrcDestMap {
		for inDestIp, inSp := range inSpMap {
			// check for consistency between the in/out direction SPs for peer IPs
			srcdestIp := inSrcIp + tunnelDirectionChar + inDestIp

			if outSp, foundPeer := correlations.OutSpSrcDestMap[inDestIp][inSrcIp]; foundPeer {
				saMatch := "N"
				if inSp.Value.SaIndex == outSp.Value.SaIndex {
					// matching SaIndex
					saMatch = "Y"
				}

				inSa := agent.FindIPSecSA(inSp.Value.SaIndex, correlations.SrcInstanceMap[inSrcIp].Config.VPP.IPSecSAs)
				if inSa != nil {
					paramsMatch := 0
					if outSa := agent.FindIPSecSA(inSp.Value.SaIndex, correlations.SrcInstanceMap[inDestIp].Config.VPP.IPSecSAs); outSa != nil {
						if inSa.Value.Spi == outSa.Value.Spi {
							paramsMatch |= 0x1
						}
						if inSa.Value.CryptoKey == outSa.Value.CryptoKey {
							paramsMatch |= 0x1 << 1
						}
						if inSa.Value.IntegKey == outSa.Value.IntegKey {
							paramsMatch |= 0x1 << 2
						}
					}

					cols := []string{
						srcdestIp, "Y", fmt.Sprint(inSp.Value.SaIndex), saMatch, fmt.Sprint(inSa.Value.Spi), inSa.Value.CryptoKey, inSa.Value.IntegKey, fmt.Sprintf("%03b\n", paramsMatch),
					}
					fmt.Fprintln(w, strings.Join(cols, "\t"))
				} else {
					cols := []string{
						srcdestIp, "Y", fmt.Sprint(inSp.Value.SaIndex), saMatch,
					}
					fmt.Fprintln(w, strings.Join(cols, "\t"))
				}
			} else {
				cols := []string{
					srcdestIp, "N", fmt.Sprint(inSp.Value.SaIndex),
				}
				fmt.Fprintln(w, strings.Join(cols, "\t"))
			}
		}
	}

	header = []string{
		"SPI", "dir", "IP in <-> out", "SA", "CRYPTO", "INTEG",
	}
	for i, h := range header {
		if h != "" {
			header[i] = colorize(color.Bold, h)
		}
	}
	fmt.Fprintln(w, strings.Join(header, "\t"))

	for spi, spList := range correlations.SpiOutSrcDestMap {
		for _, sp := range spList {
			inSrcIp := sp.Value.LocalAddrStart
			inSa := agent.FindIPSecSA(sp.Value.SaIndex, correlations.SrcInstanceMap[inSrcIp].Config.VPP.IPSecSAs)
			cols := []string{
				fmt.Sprintf("0x%x", spi), "Out", fmt.Sprintf("%s<->%s", inSrcIp, sp.Value.RemoteAddrStart),
				fmt.Sprint(sp.Value.SaIndex), inSa.Value.CryptoKey, inSa.Value.IntegKey,
			}
			fmt.Fprintln(w, strings.Join(cols, "\t"))
		}
		if _, ok := correlations.SpiInSrcDestMap[spi]; ok {
			for _, sp := range correlations.SpiInSrcDestMap[spi] {
				inSrcIp := sp.Value.LocalAddrStart
				inSa := agent.FindIPSecSA(sp.Value.SaIndex, correlations.SrcInstanceMap[inSrcIp].Config.VPP.IPSecSAs)
				cols := []string{
					fmt.Sprintf("0x%x", spi), "In", fmt.Sprintf("%s<->%s", inSrcIp, sp.Value.RemoteAddrStart),
					fmt.Sprint(sp.Value.SaIndex), inSa.Value.CryptoKey, inSa.Value.IntegKey,
				}
				fmt.Fprintln(w, strings.Join(cols, "\t"))
			}
		}
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

func vppInterfaceIPs(iface *vpp_interfaces.Interface) string {
	ips := iface.GetIpAddresses()
	vrf := iface.GetVrf()
	unnum := iface.GetUnnumbered()
	ip := "-"
	if len(ips) > 0 {
		ipsclr := []string{}
		for _, ipaddr := range ips {
			ipsclr = append(ipsclr, colorize(ipAddressColor, ipaddr))
		}

		ip = strings.Join(ipsclr, ", ")
	}
	if unnum != nil {
		ip = fmt.Sprintf("unnumbered: %s", unnum.GetInterfaceWithIp())
	}
	if vrf > 0 {
		ip += fmt.Sprintf(" (VRF %v)", colorize(color.Cyan, vrf))
	}
	return ip
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
	return colorizedUpDown(iface.Value.Enabled)
}

func colorizedUpDown(status bool) string {
	if status {
		return colorize(statusUpColor, "up")
	}
	return colorize(statusDownColor, "down")
}

func vppInterfaceStatus(iface agent.VppInterface, interfaces []agent.VppInterface) string {
	adminStatus := colorizedUpDown(iface.Value.Enabled)
	if iface.Value.GetSub() == nil {
		linkState := iface.GetLinkState()
		if linkState != iface.Value.Enabled {
			return fmt.Sprintf("link %v", colorizedUpDown(linkState))
		}
	}
	return adminStatus
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
		fieldsStr := mapValuesColorized(m, valueColor)
		return fmt.Sprintf("host_if_name:%s %v", colorize(valueColor, iface.Metadata["TAPHostIfName"]), fieldsStr)

	case vpp_interfaces.Interface_IPIP_TUNNEL:
		tun := iface.Value.GetIpip()
		var info string
		info += fmt.Sprintf("%s %s %s mode:%v", colorize(ipAddressColor, tun.SrcAddr), tunnelDirectionChar, colorize(ipAddressColor, tun.DstAddr), colorize(valueColor, tun.TunnelMode))
		return info
	}

	return interfaceLinkInfo(iface.Value.ProtoReflect())
}

func relatedInfo(conf *agent.Config, iface agent.VppInterface) string {
	var info []string

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
		info = append(info, fmt.Sprintf("ipsec SA in:%v out:%v", colorize(color.Cyan, tp.Value.SaIn), colorize(color.Cyan, tp.Value.SaOut)))
	}
	if tp := agent.FindIPSecSPFor(iface.Value.Name, conf); tp != nil {
		info = append(info, fmt.Sprintf("ipsec SPs: %v", colorize(color.Cyan, len(tp))))
	}

	// Routes
	if routes := agent.FindVppRoutesFor(iface.Value.Name, conf.VPP.Routes); routes != nil {
		info = append(info, fmt.Sprintf("routes %v", colorize(color.Cyan, len(routes))))
	}

	return strings.Join(info, ", ")
}

func vppInterfaceStats(instance *vpp.Instance, iface agent.VppInterface) string {
	stats := instance.VppStats()
	if stats == nil {
		return "-"
	}

	var s string

	padnum := func(num uint64) string {
		return fmt.Sprintf("%5d", num)
	}

	if ifaceStats, ok := stats.Interfaces[interfaceInternalName(iface)]; ok {
		var tx, rx string
		if ifaceStats.Tx != nil {
			tx = fmt.Sprintf("%v pkts / %v bytes", colorize(color.LightCyan, padnum(ifaceStats.Tx.Packets)), colorize(color.LightCyan, padnum(ifaceStats.Tx.Bytes)))
		}
		if ifaceStats.TxErrors > 0 {
			tx += fmt.Sprintf(", %v errors", colorize(color.LightRed, ifaceStats.TxErrors))
		}
		if ifaceStats.Rx != nil {
			rx = fmt.Sprintf("%v pkts / %v bytes", colorize(color.LightCyan, padnum(ifaceStats.Rx.Packets)), colorize(color.LightCyan, padnum(ifaceStats.Rx.Bytes)))
		}
		if ifaceStats.RxErrors > 0 {
			rx += fmt.Sprintf(", %v errors", colorize(color.LightRed, ifaceStats.RxErrors))
		}
		statsStr := fmt.Sprintf("%v: %24v | %v: %24v", colorize(color.LightWhite, "TX"), tx, colorize(color.LightWhite, "RX"), rx)
		if ifaceStats.Drops > 0 {
			statsStr += fmt.Sprintf(" | %v drops", colorize(color.LightYellow, ifaceStats.Drops))
		}
		return statsStr

		/*b, err := json.Marshal(ifaceStats)
		  if err != nil {
		  	logrus.Warnf("failed to marshal vpp interface stats: %v", err)
		  	return fmt.Sprintf("%+v", ifaceStats)
		  }
		  b = bytes.TrimPrefix(b, []byte("{"))
		  b = bytes.TrimSuffix(b, []byte("}"))
		  b = bytes.Replace(b, []byte(`"`), []byte(""), -1)
		  return string(b)*/
	}

	return s
}

func interfaceLinkInfo(ifaceMsg protoreflect.Message) string {
	ld := ifaceMsg.Descriptor().Oneofs().ByName("link")
	if ld == nil {
		panic(fmt.Sprintf("message %v does not have oneof with name 'link'", string(ifaceMsg.Descriptor().FullName())))
	}
	wd := ifaceMsg.WhichOneof(ld)
	if wd == nil {
		return ""
	}
	d := wd.Message()
	link := ifaceMsg.Get(wd).Message()

	m := protoFieldsToMap(d.Fields(), link)
	return mapValuesColorized(m, valueColor)
}
