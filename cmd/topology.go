package cmd

import (
	"fmt"
	"io"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"go.ligato.io/vpp-probe/vpp/topology"

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

	topo, err := topology.Build(instances)
	if err != nil {
		return fmt.Errorf("correlation failed: %w", err)
	}

	logrus.Infof("correlated %v connections ", len(topo.Connections))

	if format := opts.Format; len(format) == 0 {
		printTopologyTable(cli.Out(), instances, topo)
	} else if format == "dot" {
		topology.PrintTopologyDot(cli.Out(), instances, topo)
	} else {
		if err := formatAsTemplate(cli.Out(), format, topo); err != nil {
			return err
		}
	}

	return nil
}

func printTopologyTable(w io.Writer, instance []*vpp.Instance, info *topology.Info) {
	for _, conn := range info.Connections {
		logrus.Infof("* %v", conn)
		logrus.Debugf("%+v	<->	%+v\n", conn.Source, conn.Destination)
	}
}
