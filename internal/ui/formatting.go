package ui

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"go.ligato.io/vpp-probe/vpp"
	"go.ligato.io/vpp-probe/vpp/api"
)

func formatInterfaceIPs(IPs []string) string {
	return strings.Join(IPs, ", ")
}

func formatInterfaceVRF(vrf api.VRF) string {
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

func formatInterfaceMTU(mtu api.MTU) string {
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

func formatInterfaceStatus(status api.Status) string {
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

func updatedColor(updated time.Duration) string {
	switch {
	case updated < time.Second*15:
		return "lime"
	case updated < time.Minute*1:
		return "greenyellow"
	case updated < time.Minute*5:
		return "orange"
	case updated < time.Minute*15:
		return "darkred"
	default:
		return "gray"
	}
}

func statusColor(status vpp.Status) string {
	switch status.State {
	case vpp.StateOK:
		return "green"
	case vpp.StateChecking:
		return "yellow"
	case vpp.StateError:
		return "red"
	default:
		return "gray"
	}
}

func shortHumanDuration(d time.Duration) string {
	if seconds := int(d.Seconds()); seconds < -1 {
		return fmt.Sprintf("-")
	} else if seconds <= 0 {
		return fmt.Sprintf("now")
	} else if seconds < 60 {
		return fmt.Sprintf("%d secs", seconds)
	} else if minutes := int(d.Minutes()); minutes < 60 {
		return fmt.Sprintf("%d mins", minutes)
	} else if hours := int(d.Hours()); hours < 24 {
		return fmt.Sprintf("%d hours", hours)
	} else if hours < 24*365 {
		return fmt.Sprintf("%d days", hours/24)
	}
	return fmt.Sprintf("%d years", int(d.Hours()/24/365))
}
