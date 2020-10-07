package termui

import (
	"fmt"
	"sort"
	"strings"

	"go.ligato.io/vpp-probe/vpp/types"
)

func formatInterfaceName(iface *types.Interface) string {
	name := iface.Name
	if len(strings.TrimSpace(iface.Tag)) > 0 {
		name = fmt.Sprintf("%s (%s)", iface.Name, iface.Tag)
	}
	return fmt.Sprintf("[white]%s[-]", name)
}

func formatInterfaceIPs(IPs []string) string {
	return strings.Join(IPs, ", ")
}

func formatInterfaceVRF(vrf types.VRF) string {
	var vrfs []string
	for t, m := range map[string]uint{
		"IP4": vrf.IP4,
		"IP6": vrf.IP6,
	} {
		if m > 0 {
			vrfs = append(vrfs, fmt.Sprintf("%s: %d", t, m))
		}
	}
	sort.Strings(vrfs)
	return strings.Join(vrfs, ", ")
}

func formatInterfaceMTU(mtu types.MTU) string {
	var mtus []string
	for t, m := range map[string]uint{
		"L3":   mtu.L3,
		"IP4":  mtu.IP4,
		"IP6":  mtu.IP6,
		"MPLS": mtu.MPLS,
		"Link": mtu.Link,
	} {
		if m > 0 {
			mtus = append(mtus, fmt.Sprintf("%s: %d", t, m))
		}
	}
	sort.Strings(mtus)
	return strings.Join(mtus, ", ")
}

func formatInterfaceStatus(status types.Status) string {
	var s string
	color := "yellow"
	adminUp := status.Up
	linkUp := status.Link
	switch {
	case adminUp && linkUp:
		s = "up"
		color = "green"
	case linkUp:
		s = "down (link up)"
	case adminUp:
		s = "down (admin up)"
	case !adminUp && !linkUp:
		s = "down"
		color = "red"
	default:
		return fmt.Sprint(status)
	}
	return fmt.Sprintf("[%s]%s[-]", color, s)
}
