package agent

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/gookit/color"
	vpp_interfaces "go.ligato.io/vpp-agent/v3/proto/ligato/vpp/interfaces"
)

func PrintInstance(instance *Instance) {
	fmt.Println("----------")
	fmt.Printf("= VPP Instance: %v\n", instance.ID())
	fmt.Println("----------")

	fmt.Printf(" Version: %s\n", color.FgLightBlue.Sprint(instance.Version))
	fmt.Println()

	PrintInterfacesTable(os.Stdout, instance)
	fmt.Println()
	fmt.Printf("%d vpp interfaces\n", len(instance.VppInterfaces))

	if len(instance.LinuxInterfaces) > 0 {
		fmt.Println()
		fmt.Printf("%d linux interfaces:\n", len(instance.LinuxInterfaces))
		for _, v := range instance.LinuxInterfaces {
			fmt.Printf(" - %v:\n", v.Value)
		}
	}
	fmt.Printf("\n")
}

func PrintCLIs(instance *Instance) {
	for k, v := range instance.Extra {
		val := color.FgLightBlue.Sprint(v)
		val = "\t" + strings.ReplaceAll(val, "\n", "\n\t")
		fmt.Printf("%s:\n\n%s\n", k, val)
		fmt.Println()
	}
	fmt.Println()
}

func PrintCorrelatedNsmIpSec(out io.Writer, instances []*Instance) {
	srcMap := make(map[string]*Instance)
	inSpSrcDestMap := make(map[string]map[string]VppIPSecSP)
	outSpSrcDestMap := make(map[string]map[string]VppIPSecSP)
	// create a lookup of SP by src & dest
	for _, instance := range instances {
		ipsecSPs := instance.IPSecSPs
		for _, sp := range ipsecSPs {
			srcIp := sp.Value.LocalAddrStart
			srcMap[srcIp] = instance
			if sp.Value.IsOutbound {
				if _, ok := outSpSrcDestMap[sp.Value.LocalAddrStart]; !ok {
					outSpSrcDestMap[sp.Value.LocalAddrStart] = make(map[string]VppIPSecSP)
				}
				outSpSrcDestMap[sp.Value.LocalAddrStart][sp.Value.RemoteAddrStart] = sp
			} else {
				if _, ok := inSpSrcDestMap[sp.Value.LocalAddrStart]; !ok {
					inSpSrcDestMap[sp.Value.LocalAddrStart] = make(map[string]VppIPSecSP)
				}
				inSpSrcDestMap[sp.Value.LocalAddrStart][sp.Value.RemoteAddrStart] = sp
			}
		}
	}
	var buf bytes.Buffer
	w := tabwriter.NewWriter(&buf, 1, 8, 0, '\t', tabwriter.StripEscape)
	fmt.Fprintf(w, "\nSecurityPolicy Correlation\n%v\t%v\t%v\t%v\t%v\t%v\t\n",
		escapeClr(color.LightWhite, "inIP <-> outIp"), escapeClr(color.White, "Peer?"), escapeClr(color.White, "SA"), escapeClr(color.White, "SPI"), escapeClr(color.White, "CRYPTO"),escapeClr(color.White, "INTEG") )

	// correlate data
	for inSrcIp, inSpMap := range inSpSrcDestMap {
		for inDestIp, inSp := range inSpMap {
			// check for consistency between the in/out direction SPs for peer IPs
			saIdxColor := color.Red
			spiColor := color.Red
			cryptoColor := color.Red
			integColor := color.Red
			srcdestIp := escapeClr(color.LightWhite, inSrcIp + " <-> " + inDestIp)
			if outSp, foundPeer := outSpSrcDestMap[inDestIp][inSrcIp]; foundPeer {
				if inSp.Value.SaIndex == outSp.Value.SaIndex {
					// matching SaIndex
					saIdxColor = color.Green
				}
				inSa := FindIPSecSA(inSp.Value.SaIndex, srcMap[inSrcIp].IPSecSAs)
				if inSa != nil {
					if outSa := FindIPSecSA(inSp.Value.SaIndex, srcMap[inDestIp].IPSecSAs); outSa != nil {
						if inSa.Value.Spi == outSa.Value.Spi {
							spiColor = color.Green
						}
						if inSa.Value.CryptoKey == outSa.Value.CryptoKey {
							cryptoColor = color.Green
						}
						if inSa.Value.IntegKey == outSa.Value.IntegKey {
							integColor = color.Green
						}
					}

					fmt.Fprintf(w, "%v\t%1v\t%v\t%v\t%v\t%v\n",
						srcdestIp, escapeClr(color.Green, "Y"), escapeClr(saIdxColor, inSp.Value.SaIndex), escapeClr(spiColor, inSa.Value.Spi), escapeClr(cryptoColor, inSa.Value.CryptoKey), escapeClr(integColor, inSa.Value.IntegKey))

				} else {
					fmt.Fprintf(w, "%v\t%1v\t%v\n",
						srcdestIp, escapeClr(color.Green, "Y"), escapeClr(saIdxColor, inSp.Value.SaIndex))
				}
			} else {
				fmt.Fprintf(w, "%v\t%1v\t%v\n",
					srcdestIp, escapeClr(color.Green, "N"), escapeClr(saIdxColor, inSp.Value.SaIndex))
			}
		}
	}
	if err := w.Flush(); err != nil {
		log.Println(err)
		return
	}
	fmt.Fprint(out, buf.String())
}

func PrintInterfacesTable(out io.Writer, instance *Instance) {
	var buf bytes.Buffer
	ifaces := instance.VppInterfaces
	xconns := instance.L2XConnects
	tunprots := instance.IPSecTunProtects
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
	fmt.Fprintf(w, "\nSecurityPolicy\n%v\tIn/Out\t%v\t%v\t%v\t%v\t\n",
		escapeClr(color.LightWhite, "SrcIP <-> DestIp"), escapeClr(color.White, "SA"), escapeClr(color.White, "SPI"), escapeClr(color.White, "CRYPTO"),escapeClr(color.White, "INTEG") )
	ipsecSPs := instance.IPSecSPs
	for _, sp := range ipsecSPs {
		srcdestIp := escapeClr(color.LightWhite, sp.Value.LocalAddrStart + " <-> " + sp.Value.RemoteAddrStart)
		direction := "in"
		if sp.Value.IsOutbound {
			direction = "out"
		}
		saIdx := escapeClr(color.LightWhite, sp.Value.SaIndex)
		//endOfLine := "\n"
		sa := FindIPSecSA(sp.Value.SaIndex, instance.IPSecSAs)
		if sa != nil {
			fmt.Fprintf(w, "%v\t%3v\t%v\t%v\t%v\t%v\n",
			srcdestIp, direction, saIdx, escapeClr(color.LightWhite, sa.Value.Spi), escapeClr(color.LightWhite, sa.Value.CryptoKey), escapeClr(color.LightWhite, sa.Value.IntegKey))
		} else {
			fmt.Fprintf(w, "%v\t%3v\t%v\n",
				srcdestIp, direction, saIdx)
		}
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
