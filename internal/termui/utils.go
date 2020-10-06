package termui

import (
	"fmt"
	"sort"
	"strings"

	"go.ligato.io/vpp-probe/client"
)

func formatInterfaceMTU(mtu client.MTU) string {
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
