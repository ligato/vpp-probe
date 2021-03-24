package cmd

import (
	"fmt"
	"io"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	linux_interfaces "go.ligato.io/vpp-agent/v3/proto/ligato/linux/interfaces"
	vpp_interfaces "go.ligato.io/vpp-agent/v3/proto/ligato/vpp/interfaces"

	"go.ligato.io/vpp-probe/vpp"
)

func NewTopologyCmd(cli Cli) *cobra.Command {
	var (
		opts TopologyOptions
	)
	cmd := &cobra.Command{
		Use:     "topology [options]",
		Aliases: []string{"topo"},
		Short:   "Correlate connections from VPP instances into topology",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) >= 1 {
				opts.Src = args[0]
			}
			if len(args) >= 2 {
				opts.Dst = args[1]
			}
			return RunTopology(cli, opts)
		},
		Example: discoverExample,
	}
	flags := cmd.Flags()
	flags.StringVarP(&opts.Format, "format", "f", "", "Output format (json, yaml, go-template..)")
	return cmd
}

type TopologyOptions struct {
	Format string
	Src    string
	Dst    string
}

func RunTopology(cli Cli, opts TopologyOptions) error {
	if err := cli.Client().DiscoverInstances(cli.Queries()...); err != nil {
		return err
	}
	instances := cli.Client().Instances()

	logrus.Debugf("discovered %d vpp instances", len(instances))

	for _, instance := range instances {
		if instance.Agent() == nil {
			logrus.Debugf("agent not found for instance %v", instance.ID())
			continue
		}
		logrus.Debugf("- updating vpp info %+v: %v", instance.ID(), instance.Status())

		err := instance.Agent().UpdateInstanceInfo()
		if err != nil {
			logrus.Errorf("instance %v error: %v", instance.ID(), err)
			continue
		}
	}

	connections, err := correlateConnections(instances)
	if err != nil {
		return fmt.Errorf("correlation failed: %w", err)
	}

	logrus.Infof("correlated %v connections ", len(connections))

	if format := opts.Format; len(format) == 0 {
		printTopologyTable(cli.Out(), instances, connections)
	} else if format == "dot" {
		printTopologyDot(cli.Out(), instances, connections)
	} else {
		if err := formatAsTemplate(cli.Out(), format, connections); err != nil {
			return err
		}
	}
	return nil
}

func printTopologyTable(w io.Writer, instance []*vpp.Instance, connections []*Connection) {
	for _, conn := range connections {
		logrus.Infof("* %v", conn)
		logrus.Debugf("%+v	<->	%+v\n", conn.Source, conn.Destination)
	}
}

func printTopologyDot(w io.Writer, instances []*vpp.Instance, connections []*Connection) {
	var cluster string
	fmt.Fprintln(w, "digraph G {")
	for _, instance := range instances {
		if c := instance.Handler().Metadata()["cluster"]; c != cluster {
			if cluster != "" {
				fmt.Fprintln(w, "}")
			}
			fmt.Fprintf(w, "subgraph \"cluster_%s\" {\n", c)
			fmt.Fprintf(w, "label=%q;\n", c)
			cluster = c
		}

		fmt.Fprintf(w, "subgraph \"cluster_%s\" {\n", instance.ID())
		fmt.Fprintf(w, "label=%q;\n", instance.String())

		fmt.Fprintf(w, "subgraph \"cluster_%s_vpp\" {\n", instance.ID())
		fmt.Fprintln(w, `label="VPP";`)
		fmt.Fprintln(w, `node [style=filled,color=lightblue];`)
		for _, iface := range instance.Agent().Config.VPP.Interfaces {
			if iface.Index() == 0 {
				continue
			}
			id := fmt.Sprintf("%v_%v", instance, iface.Value.GetName())
			fmt.Fprintf(w, "%q [label=%q];\n", id, iface.Value.GetName())
		}
		fmt.Fprintln(w, "}")

		for _, iface := range instance.Agent().Config.Linux.Interfaces {
			name := fmt.Sprintf("LINUX-%v", iface.Value.GetName())
			if iface.Value.GetNamespace().GetReference() != "" {
				name += fmt.Sprintf("-NS-%s", iface.Value.GetNamespace().GetReference())
			}
			id := fmt.Sprintf("%v_%v", instance, name)
			fmt.Fprintf(w, "%q [label=%q,style=filled,color=salmon];\n", id, name)
		}
		fmt.Fprintln(w, "}")
	}
	fmt.Fprintln(w, "}")
	for _, conn := range connections {
		fmt.Fprintf(w, "%v;\n", conn)
	}
	fmt.Fprintln(w, "}")
}

type Endpoint struct {
	Instance  *vpp.Instance
	Interface string
	Linux     bool
	Namespace string
}

type Connection struct {
	Source      Endpoint
	Destination Endpoint
}

func (c Connection) String() string {
	src := c.Source.Interface
	dst := c.Destination.Interface

	if c.Source.Linux {
		src = fmt.Sprintf("LINUX-%s", src)
	}
	if c.Destination.Linux {
		dst = fmt.Sprintf("LINUX-%s", dst)
	}
	if c.Source.Namespace != "" {
		src += fmt.Sprintf("-NAMESPACE-%s", c.Source.Namespace)
	}
	if c.Destination.Namespace != "" {
		dst += fmt.Sprintf("-NAMESPACE-%s", c.Destination.Namespace)
	}
	src = fmt.Sprintf("%v_%v", c.Source.Instance, src)
	dst = fmt.Sprintf("%v_%v", c.Destination.Instance, dst)
	return fmt.Sprintf("%q -> %q", src, dst)
}

func correlateConnections(instances []*vpp.Instance) ([]*Connection, error) {
	var connections []*Connection

	addConn := func(src, dst Endpoint) {
		conn := &Connection{
			Source:      src,
			Destination: dst,
		}
		connections = append(connections, conn)
	}

	logrus.Debugf("starting correlation for %v interfaces", len(instances))

	for _, instance := range instances {
		logrus.Debugf("correlating instance: %+v", instance)

		// correlate VPP interfaces
		for _, iface := range instance.Agent().Config.VPP.Interfaces {
			switch iface.Value.GetType() {
			case vpp_interfaces.Interface_MEMIF:
				memif1 := iface.Value.GetMemif()
				for _, instance2 := range instances {
					for _, iface2 := range instance2.Agent().Config.VPP.Interfaces {
						if instance.ID() == instance2.ID() && iface.Key == iface2.Key {
							continue
						}
						if iface2.Value.GetType() != vpp_interfaces.Interface_MEMIF {
							continue
						}
						memif2 := iface2.Value.GetMemif()
						if memif1.GetId() != memif2.GetId() {
							continue
						}
						if iface.Metadata["inode"] != iface2.Metadata["inode"] {
							continue
						}
						addConn(Endpoint{
							Instance:  instance,
							Interface: iface.Value.Name,
						}, Endpoint{
							Instance:  instance2,
							Interface: iface2.Value.Name,
						})
					}
				}
			case vpp_interfaces.Interface_AF_PACKET:
				addConn(Endpoint{
					Instance:  instance,
					Interface: iface.Value.Name,
				}, Endpoint{
					Instance:  instance,
					Interface: iface.Value.GetAfpacket().HostIfName,
					Linux:     true,
				})
				addConn(Endpoint{
					Instance:  instance,
					Interface: iface.Value.GetAfpacket().HostIfName,
					Linux:     true,
				}, Endpoint{
					Instance:  instance,
					Interface: iface.Value.Name,
				})
			case vpp_interfaces.Interface_TAP:

			case vpp_interfaces.Interface_VXLAN_TUNNEL:
				vxlan := iface.Value.GetVxlan()
				srcAddr := vxlan.GetSrcAddress()
				dstAddr := vxlan.GetDstAddress()
				for _, instance2 := range instances {
					for _, iface2 := range instance2.Agent().Config.VPP.Interfaces {
						if instance.ID() == instance2.ID() && iface.Key == iface2.Key {
							continue
						}
						if iface2.Value.GetType() != vpp_interfaces.Interface_VXLAN_TUNNEL {
							continue
						}
						vxlan2 := iface2.Value.GetVxlan()
						if vxlan.GetVni() != vxlan2.GetVni() {
							continue
						}
						if srcAddr != vxlan2.GetDstAddress() ||
							dstAddr != vxlan2.GetSrcAddress() {
							continue
						}
						addConn(Endpoint{
							Instance:  instance,
							Interface: iface.Value.Name,
						}, Endpoint{
							Instance:  instance2,
							Interface: iface2.Value.Name,
						})
					}
				}
			}
		}

		// correlate Linux interfaces
		for _, iface := range instance.Agent().Config.Linux.Interfaces {
			switch iface.Value.GetType() {
			case linux_interfaces.Interface_VETH:
				veth2 := instance.Agent().Config.GetLinuxInterface(iface.Value.GetVeth().PeerIfName)
				if veth2 == nil {
					logrus.Warnf("could not find peer veth for: %v", iface)
					continue
				}
				addConn(Endpoint{
					Instance:  instance,
					Interface: iface.Value.Name,
					Linux:     true,
					Namespace: iface.Value.GetNamespace().GetReference(),
				}, Endpoint{
					Instance:  instance,
					Interface: veth2.Value.Name,
					Linux:     true,
					Namespace: veth2.Value.GetNamespace().GetReference(),
				})
			case linux_interfaces.Interface_TAP_TO_VPP:
				tap2 := instance.Agent().Config.GetVppInterface(iface.Value.GetTap().VppTapIfName)
				if tap2 == nil {
					logrus.Warnf("could not find vpp tap for: %v", iface)
					continue
				}
				addConn(Endpoint{
					Instance:  instance,
					Interface: iface.Value.Name,
					Linux:     true,
					Namespace: iface.Value.GetNamespace().GetReference(),
				}, Endpoint{
					Instance:  instance,
					Interface: tap2.Value.GetName(),
				})
				addConn(Endpoint{
					Instance:  instance,
					Interface: tap2.Value.GetName(),
				}, Endpoint{
					Instance:  instance,
					Interface: iface.Value.Name,
					Linux:     true,
					Namespace: iface.Value.GetNamespace().GetReference(),
				})
			}
		}

		// correlate L2 xconnects
		for _, l2xc := range instance.Agent().Config.VPP.L2XConnects {
			addConn(Endpoint{
				Instance:  instance,
				Interface: l2xc.Value.TransmitInterface,
			}, Endpoint{
				Instance:  instance,
				Interface: l2xc.Value.ReceiveInterface,
			})
		}
	}

	return connections, nil
}
