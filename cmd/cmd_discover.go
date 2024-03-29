package cmd

import (
	"bytes"
	"fmt"
	"io"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"go.ligato.io/vpp-probe/client"
	"go.ligato.io/vpp-probe/pkg/strutil"
	"go.ligato.io/vpp-probe/vpp/agent"

	"go.ligato.io/vpp-probe/vpp"
)

const discoverExample = `  # Discover VPP instances in Kubernetes pods
  vpp-probe discover -e kube

  # Discover VPP instances from multiple kubeconfig contexts in single run 
  vpp-probe discover -e kube --kubecontext="demo1,demo2"

  # Discover VPP instances in Docker containers
  vpp-probe discover -e docker

  # Discover local VPP instance
  vpp-probe discover`

func NewDiscoverCmd(cli Cli) *cobra.Command {
	var (
		opts DiscoverOptions
	)
	cmd := &cobra.Command{
		Use:   "discover [options]",
		Short: "Discover running VPP instances",
		RunE: func(cmd *cobra.Command, args []string) error {
			return RunDiscover(cli, opts)
		},
		Example: discoverExample,
	}
	flags := cmd.Flags()
	flags.StringVarP(&opts.Format, "format", "f", "", "Output format (json, yaml, go-template..)")
	flags.BoolVar(&opts.IPsecAgg, "ipsec-agg", false, "Print aggregated IPSec info")
	return cmd
}

type DiscoverOptions struct {
	Format   string
	IPsecAgg bool
}

func RunDiscover(cli Cli, opts DiscoverOptions) error {
	// TODO: refactor this to run discovery and only print list of discovered
	//  instances and move retrieval of agent config (interfaces) to a separate
	//  command that will support selecting specific instance

	if err := cli.Client().DiscoverInstances(cli.Queries()...); err != nil {
		return err
	}

	instances := cli.Client().Instances()

	logrus.Debugf("discovered %d vpp instances", len(instances))

	instch := make(chan *agent.Instance, len(instances))

	if err := client.RunOnInstances(instances, func(instance *vpp.Instance) error {
		if instance.Agent() == nil {
			return fmt.Errorf("agent not found for instance %v", instance.ID())
		}
		logrus.Debugf("- updating vpp info %+v: %v", instance.ID(), instance.Status())

		err := instance.Agent().UpdateInstanceInfo()
		if err != nil {
			return fmt.Errorf("instance %v error: %v", instance.ID(), err)
		}
		instch <- instance.Agent()

		if format := opts.Format; len(format) == 0 {
			printDiscoverTable(cli.Out(), instance)
		} else {
			if err := formatAsTemplate(cli.Out(), format, instance); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return err
	}
	close(instch)

	var agentInstances []*agent.Instance
	for inst := range instch {
		agentInstances = append(agentInstances, inst)
	}

	if opts.IPsecAgg {
		logrus.Infof("Aggregating IPSec info for instances")

		ipsecAgg, err := agent.CorrelateIPSec(agentInstances)
		if err != nil {
			logrus.Warnf("correlating IPSec failed: %v", err)
		} else {
			printDiscoverIPSecAggr(cli.Out(), ipsecAgg)
		}
	}

	return nil
}

func printDiscoverTable(out io.Writer, instance *vpp.Instance) {
	var buf bytes.Buffer

	printInstanceHeader(&buf, instance.Handler())

	printDiscoveredInstance(strutil.IndentedWriter(&buf), instance)

	fmt.Fprint(out, renderColor(buf.String()))
}

func printDiscoveredInstance(out io.Writer, instance *vpp.Instance) {
	config := instance.Agent().Config

	// Info
	{
		vppInfo := instance.VppInfo()
		fmt.Fprintf(out, "VPP version: %s | uptime: %v\n", colorize(noteColor, vppInfo.Build.Version), colorize(noteColor, vppInfo.Runtime.Uptime))
	}
	fmt.Fprintln(out)

	// VPP
	{
		if len(config.VPP.Interfaces) > 0 {
			fmt.Fprintln(out, colorize(headerColor, "VPP"))
			w := strutil.IndentedWriter(out)
			PrintVPPInterfacesTable(w, instance)
		} else {
			fmt.Fprintln(out, colorize(nonAvailableColor, "No VPP interfaces configured"))
		}
	}
	fmt.Fprintln(out)

	// Linux
	{
		if len(config.Linux.Interfaces) > 0 {
			fmt.Fprintln(out, headerColor.Sprint("Linux"))
			w := strutil.IndentedWriter(out)
			PrintLinuxInterfacesTable(w, instance)
		} else {
			fmt.Fprintln(out, colorize(nonAvailableColor, "No linux interfaces configured"))
		}
	}
	fmt.Fprintln(out)
}

func printDiscoverIPSecAggr(out io.Writer, ipsecCorrelations *agent.IPSecCorrelations) {
	var buf bytes.Buffer

	printSectionHeader(&buf, []string{"Aggregated IPSec info"})

	PrintCorrelatedIpSec(strutil.IndentedWriter(&buf), ipsecCorrelations)

	fmt.Fprint(out, renderColor(buf.String()))
}
