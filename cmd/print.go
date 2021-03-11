package cmd

import (
	"bytes"
	"fmt"
	//"go.ligato.io/vpp-probe/vpp"
	"io"
	"log"
	"strings"
	"text/tabwriter"

	"github.com/gookit/color"
	linux_namespace "go.ligato.io/vpp-agent/v3/proto/ligato/linux/namespace"
	vpp_interfaces "go.ligato.io/vpp-agent/v3/proto/ligato/vpp/interfaces"
	"go.ligato.io/vpp-probe/probe"
	"go.ligato.io/vpp-probe/providers"

	"go.ligato.io/vpp-probe/vpp/agent"
)

const (
	tunnelDirectionChar = `->`
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

		cols := []string{
			idx, internal, name, typ, state, ips, mtu, info, other,
		}
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

func PrintCorrelatedNsmIpSec(out io.Writer, instances []*agent.Instance) {
	srcMap := make(map[string]*agent.Instance)
	inSpSrcDestMap := make(map[string]map[string]agent.VppIPSecSP)
	outSpSrcDestMap := make(map[string]map[string]agent.VppIPSecSP)
	// create a lookup of SP by src & dest
	for _, instance := range instances {
		if !HasAnyIPSecConfig(instance) {
			continue
		}
		ipsecSPs := instance.Config.VPP.IPSecSPs
		for _, sp := range ipsecSPs {
			srcIp := sp.Value.LocalAddrStart
			srcMap[srcIp] = instance
			if sp.Value.IsOutbound {
				if _, ok := outSpSrcDestMap[sp.Value.LocalAddrStart]; !ok {
					outSpSrcDestMap[sp.Value.LocalAddrStart] = make(map[string]agent.VppIPSecSP)
				}
				outSpSrcDestMap[sp.Value.LocalAddrStart][sp.Value.RemoteAddrStart] = sp
			} else {
				if _, ok := inSpSrcDestMap[sp.Value.LocalAddrStart]; !ok {
					inSpSrcDestMap[sp.Value.LocalAddrStart] = make(map[string]agent.VppIPSecSP)
				}
				inSpSrcDestMap[sp.Value.LocalAddrStart][sp.Value.RemoteAddrStart] = sp
			}
		}
	}
	if len(inSpSrcDestMap) == 0 {
		// no instances with IPSec config
		return
	}
	var buf bytes.Buffer
	w := tabwriter.NewWriter(&buf, 0, 8, 1, '\t', tabwriter.StripEscape|tabwriter.FilterHTML|tabwriter.DiscardEmptyColumns)
	//fmt.Fprintf(w, "\nSecurityPolicy Correlation\n%v\t%v\t%v\t%v\t%v\t%v\t\n",
	//	escapeClr(color.LightWhite, "inIP <-> outIp"), escapeClr(color.White, "Peer?"), escapeClr(color.White, "SA"), escapeClr(color.White, "SPI"), escapeClr(color.White, "CRYPTO"),escapeClr(color.White, "INTEG") )

	header := []string{
		"inIP<->outIp", "Peer?", "SA", "SA-match?", "SPI", "CRYPTO", "INTEG", "MatchFlags",
	}
	for i, h := range header {
		if h != "" {
			header[i] = colorize(color.Bold, h)
		}
	}
	fmt.Fprintln(w, strings.Join(header, "\t"))
	// correlate data
	for inSrcIp, inSpMap := range inSpSrcDestMap {
		for inDestIp, inSp := range inSpMap {
			// check for consistency between the in/out direction SPs for peer IPs
			/*
			saIdxColor := color.Red
			spiColor := color.Red
			cryptoColor := color.Red
			integColor := color.Red

			 */
			srcdestIp := inSrcIp + " <-> " + inDestIp
			if outSp, foundPeer := outSpSrcDestMap[inDestIp][inSrcIp]; foundPeer {
				saMatch := "N"
				if inSp.Value.SaIndex == outSp.Value.SaIndex {
					// matching SaIndex
					saMatch = "Y"
				}

				inSa := FindIPSecSA(inSp.Value.SaIndex, srcMap[inSrcIp].Config.VPP.IPSecSAs)
				if inSa != nil {
					paramsMatch := 0
					if outSa := FindIPSecSA(inSp.Value.SaIndex, srcMap[inDestIp].Config.VPP.IPSecSAs); outSa != nil {
						if inSa.Value.Spi == outSa.Value.Spi {
							//spiColor = color.Green
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

func colorizedStatus(status bool) string {
	if status {
		return colorize(statusUpColor, "up")
	}
	return colorize(statusDownColor, "down")
}

func interfaceStatus(iface agent.VppInterface) string {
	adminStatus := colorizedStatus(iface.Value.Enabled)
	linkState := iface.GetLinkState()
	if linkState != iface.Value.Enabled {
		return fmt.Sprintf("%v (link %v)", adminStatus, colorizedStatus(linkState))
	}
	return adminStatus
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

func FindIPSecSA(saIdx uint32, ipsecSas []agent.VppIPSecSA) *agent.VppIPSecSA {
	for _, sa := range ipsecSas {
		if saIdx == sa.Value.Index {
			return &sa
		}
	}
	return nil
}

func HasAnyIPSecConfig(vpp *agent.Instance) bool {
	switch {
	case len(vpp.Config.VPP.IPSecTunProtects) > 0,
		len(vpp.Config.VPP.IPSecSAs) > 0:
		return true
	case len(vpp.Config.VPP.IPSecSPs) > 0,
		len(vpp.Config.VPP.IPSecSAs) > 0:
		return true
	}
	return false
}
