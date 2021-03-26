package topology

import (
	"fmt"
	"io"

	"github.com/segmentio/textio"
	"go.ligato.io/vpp-probe/vpp"
)

func PrintTopologyDot(w io.Writer, instances []*vpp.Instance, info *Info) {
	fmt.Fprintln(w, "digraph G {")

	{
		w := prefixWriter(w)
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
				fmt.Fprintf(w, "label=%q;\n", c)
				fmt.Fprintf(w, "bgcolor=%s;\n", "LightYellow")
				cluster = c
			}

			// Host
			fmt.Fprintln(w)
			fmt.Fprintf(w, "subgraph \"cluster_%s\" {\n", instance.ID())
			{
				w := prefixWriter(w)
				fmt.Fprintf(w, "label=%q;\n", instance.String())
				fmt.Fprintf(w, "bgcolor=%s;\n", "lightgray")

				// VPP instance
				fmt.Fprintln(w)
				fmt.Fprintf(w, "subgraph \"cluster_%s_vpp\" {\n", instance.ID())
				{
					w := prefixWriter(w)
					fmt.Fprintln(w, `label="VPP";`)
					fmt.Fprintf(w, "style=%s;\n", "solid")
					fmt.Fprintf(w, "bgcolor=%s;\n", "lightcyan")
					fmt.Fprintln(w)
					fmt.Fprintln(w, `node [style=filled,color=lightblue];`)

					// VPP Interfaces
					for _, iface := range instance.Agent().Config.VPP.Interfaces {
						if iface.Index() == 0 {
							continue
						}
						id := fmt.Sprintf("%v_%v", instance, iface.Value.GetName())

						fmt.Fprintf(w, "%q [label=%q];\n", id, iface.Value.GetName())
					}
				}
				fmt.Fprintln(w, "}")

				// Linux Interfaces
				for _, iface := range instance.Agent().Config.Linux.Interfaces {
					label := fmt.Sprintf("%v (%s)", iface.Value.GetName(), iface.Value.HostIfName)
					name := fmt.Sprintf("LINUX-%v", iface.Value.GetName())
					if iface.Value.GetNamespace().GetReference() != "" {
						name += fmt.Sprintf("-NS-%s", iface.Value.GetNamespace().GetReference())
						label += fmt.Sprintf("\n%s", iface.Value.GetNamespace().GetReference())
					}
					id := fmt.Sprintf("%v_%v", instance, name)

					fmt.Fprintf(w, "%q [label=%q,style=%q,fillcolor=%q];\n", id, label, "solid,filled", "salmon")
				}
			}
			fmt.Fprintln(w, "}")
		}
		fmt.Fprintln(w, "}")
		fmt.Fprintln(w)

		for _, conn := range info.Connections {
			fmt.Fprintf(w, "%v;\n", conn)
		}
	}

	fmt.Fprintln(w, "}")
}

func prefixWriter(w io.Writer) *textio.PrefixWriter {
	return textio.NewPrefixWriter(w, "  ")
}
