package cmd

import (
	"fmt"
	"io"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"go.ligato.io/vpp-probe/vpp/topology"

	"go.ligato.io/vpp-probe/vpp"
)

const topologyExample = `  # Print correlated connections from two clusters defined in kubeconfig files
  vpp-probe --kubeconfig="/path/to/kubeconfig1,/path/to/kubeconfig2" topology

  # Print correlated connections using Graphviz format
  vpp-probe --kubeconfig="/path/to/kubeconfig1,/path/to/kubeconfig2" topology -f dot

  # Render correlated connections to image
  vpp-probe --kubeconfig="/path/to/kubeconfig1,/path/to/kubeconfig2" topology -f dot | dot -Tpng -o graph.png
  NOTE: Graphviz must be installed (apt install graphviz)
`

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
		Example: topologyExample,
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

	logrus.Infof("discovered %d vpp instances", len(instances))

	var errs []error

	for _, instance := range instances {
		if instance.Agent() == nil {
			logrus.Debugf("agent not found for instance %v", instance.ID())
			continue
		}
		logrus.Debugf("- updating vpp info %+v: %v", instance.ID(), instance.Status())

		err := instance.Agent().UpdateInstanceInfo()
		if err != nil {
			errs = append(errs, err)
			logrus.Errorf("instance %v error: %v", instance.ID(), err)
			continue
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("cannot build topology, %d/%d instances failed to update info", len(errs), len(instances))
	}

	topo, err := topology.Build(instances)
	if err != nil {
		return fmt.Errorf("correlation failed: %w", err)
	}

	logrus.Infof("correlated %v connections for %d instances", len(topo.Connections), len(instances))

	if format := opts.Format; len(format) == 0 {
		printTopologyTable(cli.Out(), instances, topo)
	} else if format == "dot" {
		return topology.PrintTopologyDot(cli.Out(), instances, topo)
	} else {
		return formatAsTemplate(cli.Out(), format, topo)
	}

	return nil
}

func printTopologyTable(w io.Writer, instances []*vpp.Instance, topop *topology.Info) {
	fmt.Fprintf(w, "Instances (%d)\n", len(instances))
	for _, instance := range instances {
		fmt.Fprintf(w, " - %v\n", instance)
	}

	if len(topop.Networks) > 0 {
		fmt.Fprintf(w, "Networks (%d)\n", len(topop.Networks))
		for _, network := range topop.Networks {
			fmt.Fprintf(w, " - %+v", network)
		}
	}

	fmt.Fprintf(w, "Connections (%d)\n", len(topop.Connections))
	for _, conn := range topop.Connections {
		fmt.Fprintf(w, " - %+v <=> %+v\n", conn.Source, conn.Destination)
	}
}
