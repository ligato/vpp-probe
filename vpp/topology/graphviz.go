package topology

import (
	"fmt"
	"io"
	"strings"

	"github.com/segmentio/textio"
	"go.ligato.io/vpp-probe/vpp"
)

const (
	graphBgColor        = "LightGray"
	clusterBgColor      = "Snow"
	hostBgColor         = "OldLace"
	vppBgColor          = "LightCyan"
	vppIfaceFillColor   = "LightBlue"
	linuxIfaceFillColor = "Khaki"
)

func PrintTopologyDot(w io.Writer, instances []*vpp.Instance, info *Info) error {
	fprintSection(w, "digraph G", func(w io.Writer) {
		fmt.Fprintf(w, "rankdir=%s;\n", "LR")
		fmt.Fprintf(w, "bgcolor=%s;\n", graphBgColor)

		var cluster string
		for _, instance := range instances {

			// Cluster
			if c := instance.Handler().Metadata()["cluster"]; c != cluster {
				if cluster != "" {
					fmt.Fprintln(w, "}")
					fmt.Fprintln(w)
				}
				fmt.Fprintln(w)
				fmt.Fprintf(w, "subgraph \"cluster_%s\" {\n", c)
				label := fmt.Sprintf("%v [cluster]", c)
				fmt.Fprintf(w, "label=%q;\n", label)
				fmt.Fprintf(w, "bgcolor=%s;\n", clusterBgColor)
				cluster = c
			}

			// Host
			fmt.Fprintln(w)
			fmt.Fprintf(w, "subgraph \"cluster_%s\" {\n", instance.ID())
			{
				w := prefixWriter(w)

				label := fmt.Sprintf("%v [host]", instance.String())
				fmt.Fprintf(w, "label=%q;\n", label)
				fmt.Fprintf(w, "bgcolor=%s;\n", hostBgColor)
				fmt.Fprintln(w, `node [style="solid,filled"];`)

				// VPP instance
				fmt.Fprintln(w)
				fmt.Fprintf(w, "subgraph \"cluster_%s_vpp\" {\n", instance.ID())
				{
					w := prefixWriter(w)

					fmt.Fprintln(w, `label="VPP";`)
					fmt.Fprintf(w, "style=%s;\n", "solid")
					fmt.Fprintf(w, "bgcolor=%s;\n", vppBgColor)
					fmt.Fprintln(w)
					fmt.Fprintln(w, `node [style="solid,filled",fillcolor="lightblue"];`)

					// VPP Interfaces
					for _, iface := range instance.Agent().Config.VPP.Interfaces {
						if iface.Index() == 0 {
							continue
						}
						id := fmt.Sprintf("%v_%v", instance.ID(), iface.Value.GetName())
						label := fmt.Sprintf("%v\n(%s)", iface.Value.GetName(), iface.Metadata["InternalName"])
						if ips := iface.Value.GetIpAddresses(); len(ips) > 0 {
							label += fmt.Sprintf("\n%s", strings.Join(ips, "\n"))
						}
						fillcolor := vppIfaceFillColor
						fmt.Fprintf(w, "%q [label=%q,fillcolor=%s];\n", id, label, fillcolor)
					}
				}
				fmt.Fprintln(w, "}")

				// Linux Interfaces
				for _, iface := range instance.Agent().Config.Linux.Interfaces {
					label := fmt.Sprintf("%v\n(%s)", iface.Value.GetName(), iface.Value.HostIfName)
					name := fmt.Sprintf("LINUX-%v", iface.Value.GetName())
					if ips := iface.Value.GetIpAddresses(); len(ips) > 0 {
						label += fmt.Sprintf("\n%s", strings.Join(ips, "\n"))
					}
					if iface.Value.GetNamespace().GetReference() != "" {
						name += fmt.Sprintf("-NS-%s", iface.Value.GetNamespace().GetReference())
						label += fmt.Sprintf("\nNS: %s", iface.Value.GetNamespace().GetReference())
					}
					id := fmt.Sprintf("%v_%v", instance.ID(), name)
					fillcolor := linuxIfaceFillColor
					fmt.Fprintf(w, "%q [label=%q,style=%q,fillcolor=%q];\n", id, label, "solid,filled", fillcolor)
				}
			}
			fmt.Fprintln(w, "}")
		}
		if cluster != "" {
			fmt.Fprintln(w, "}")
		}
		fmt.Fprintln(w)

		// Connections
		for _, c := range info.Connections {
			src := c.Source.Interface
			dst := c.Destination.Interface
			if c.Source.Type == LinuxNetwork {
				src = fmt.Sprintf("LINUX-%s", src)
			}
			if c.Destination.Type == LinuxNetwork {
				dst = fmt.Sprintf("LINUX-%s", dst)
			}
			if c.Source.Namespace != "" {
				src += fmt.Sprintf("-NS-%s", c.Source.Namespace)
			}
			if c.Destination.Namespace != "" {
				dst += fmt.Sprintf("-NS-%s", c.Destination.Namespace)
			}
			src = fmt.Sprintf("%v_%v", c.Source.Instance, src)
			dst = fmt.Sprintf("%v_%v", c.Destination.Instance, dst)
			label := c.Metadata["type"]
			color := "black"
			if strings.Contains(c.Metadata["state"], "down") {
				color = "orangered"
			}

			fmt.Fprintf(w, "%q -> %q [color=%q,label=%q];\n", src, dst, color, label)
		}

	})

	return nil
}

func fprintSection(w io.Writer, section string, fn func(io.Writer)) {
	fmt.Fprintln(w, section, "{")
	{
		w := prefixWriter(w)
		fn(w)
	}
	fmt.Fprintln(w, "}")
}

func prefixWriter(w io.Writer) *textio.PrefixWriter {
	return textio.NewPrefixWriter(w, "  ")
}
