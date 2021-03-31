package topology

import (
	"fmt"
	"io"
	"strings"

	"github.com/segmentio/textio"
	"go.ligato.io/vpp-probe/vpp"
	"go.ligato.io/vpp-probe/vpp/agent"
)

func PrintTopologyDot(w io.Writer, instances []*vpp.Instance, info *Info) error {
	fprintSection(w, "digraph G", func(writer io.Writer) {
		fmt.Fprintf(w, "rankdir=%s;\n", "LR")
		fmt.Fprintf(w, "bgcolor=%s;\n", "WhiteSmoke")

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
				fmt.Fprintf(w, "bgcolor=%s;\n", "OldLace")
				cluster = c
			}

			// Host
			fmt.Fprintln(w)
			fmt.Fprintf(w, "subgraph \"cluster_%s\" {\n", instance.ID())
			{
				w := prefixWriter(w)

				label := fmt.Sprintf("%v [host]", instance.String())
				fmt.Fprintf(w, "label=%q;\n", label)
				fmt.Fprintf(w, "bgcolor=%s;\n", "LightYellow")
				fmt.Fprintln(w, `node [style="solid,filled"];`)

				// VPP instance
				fmt.Fprintln(w)
				fmt.Fprintf(w, "subgraph \"cluster_%s_vpp\" {\n", instance.ID())
				{
					w := prefixWriter(w)

					fmt.Fprintln(w, `label="VPP";`)
					fmt.Fprintf(w, "style=%s;\n", "solid")
					fmt.Fprintf(w, "bgcolor=%s;\n", "LightCyan")
					fmt.Fprintln(w)
					fmt.Fprintln(w, `node [style="solid,filled",fillcolor="lightblue"];`)

					// VPP Interfaces
					for _, iface := range instance.Agent().Config.VPP.Interfaces {
						if iface.Index() == 0 {
							continue
						}
						id := fmt.Sprintf("%v_%v", instance, iface.Value.GetName())
						label := fmt.Sprintf("%v\n(%s)", iface.Value.GetName(), iface.Metadata["InternalName"])
						if ips := iface.Value.GetIpAddresses(); len(ips) > 0 {
							label += fmt.Sprintf("\n%s", strings.Join(ips, "\n"))
						}
						fillcolor := "LightSteelBlue"
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
					id := fmt.Sprintf("%v_%v", instance, name)
					fillcolor := "Tortoise"
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
			if c.Source.Linux {
				src = fmt.Sprintf("LINUX-%s", src)
			}
			if c.Destination.Linux {
				dst = fmt.Sprintf("LINUX-%s", dst)
			}
			if c.Source.Namespace != "" {
				src += fmt.Sprintf("-NS-%s", c.Source.Namespace)
			}
			if c.Destination.Namespace != "" {
				dst += fmt.Sprintf("-NS-%s", c.Destination.Namespace)
			}
			src = fmt.Sprintf("%v_%v", c.Source.instance, src)
			dst = fmt.Sprintf("%v_%v", c.Destination.instance, dst)
			label := c.Metadata["type"]

			fmt.Fprintf(w, "%q -> %q [label=%q];\n", src, dst, label)
		}

	})

	return nil
}

func linuxInterfaceNode(instance *vpp.Instance, iface *agent.LinuxInterface) (id, label string) {
	label = fmt.Sprintf("%v (%s)", iface.Value.GetName(), iface.Value.HostIfName)
	name := fmt.Sprintf("LINUX-%v", iface.Value.GetName())
	if iface.Value.GetNamespace().GetReference() != "" {
		name += fmt.Sprintf("-NS-%s", iface.Value.GetNamespace().GetReference())
		label += fmt.Sprintf("\nNS: %s", iface.Value.GetNamespace().GetReference())
	}
	id = fmt.Sprintf("%v_%v", instance, name)
	return id, label
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
