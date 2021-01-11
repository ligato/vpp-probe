package cmd

import (
	"fmt"
	"io"

	"github.com/gookit/color"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"go.ligato.io/vpp-probe/providers"
	"go.ligato.io/vpp-probe/vpp/agent"
)

const discoverExample = `  # Discover VPP instances in Kubernetes pods with label "app=vpp"
  vpp-probe discover -e kube -q "label=app=vpp"

  # Discover VPP instances in Docker container with name "vpp1"
  vpp-probe discover -e docker -q  "name=vpp1"

  # Discover instances running locally
  vpp-probe discover`

func NewDiscoverCmd(cli *ProbeCli) *cobra.Command {
	var (
		opts DiscoverOptions
	)
	cmd := &cobra.Command{
		Use:   "discover",
		Short: "Discover running VPP instances",
		RunE: func(cmd *cobra.Command, args []string) error {
			return RunDiscover(cli, opts)
		},
		Example: discoverExample,
	}
	flags := cmd.Flags()
	flags.StringVarP(&opts.Format, "format", "f", "", "Output format.")
	flags.BoolVar(&opts.PrintCLIs, "printclis", false, "Print output from CLI commands for each instance.")
	flags.StringSliceVar(&opts.ExtraCLIs, "extraclis", nil, "Additional CLI commands to run for each instance.")
	return cmd
}

type DiscoverOptions struct {
	ExtraCLIs []string
	PrintCLIs bool
	Format    string
}

func RunDiscover(cli *ProbeCli, opts DiscoverOptions) error {
	if err := cli.Controller().DiscoverInstances(cli.Queries()...); err != nil {
		return err
	}

	instances := cli.Controller().Instances()
	logrus.Debugf("discovered %d vpp instances", len(instances))

	var agentInstances []*agent.Instance
	for _, instance := range instances {
		logrus.Debugf("- checking instance %+v: %v", instance.ID(), instance.Status())

		vpp, err := agent.NewInstance(instance.Handler())
		if err != nil {
			logrus.Errorf("instance %v error: %v", instance.ID(), err)
			continue
		}

		vpp.Version = instance.VersionInfo().Version
		if opts.PrintCLIs {
			agent.RunCLIs(vpp, opts.ExtraCLIs)
		}

		agentInstances = append(agentInstances, vpp)

		if format := opts.Format; len(format) == 0 {
			printDiscoverTable(cli.Out(), vpp, opts.PrintCLIs)
		} else {
			if err := formatAsTemplate(cli.Out(), format, vpp); err != nil {
				return err
			}
		}
	}

	return nil
}

func printDiscoverTable(out io.Writer, instance *agent.Instance, printClis bool) {
	printInstanceHeader(out, instance)
	agent.PrintInstance(out, instance)
	if printClis {
		agent.PrintCLIs(out, instance)
	}
}

func printInstanceHeader(out io.Writer, instance *agent.Instance) {
	header := "Instance"
	metadata := instance.Handler.Metadata()

	switch metadata["env"] {
	case providers.Kube:
		header = fmt.Sprintf("cluster: %s | pod: %s | namespace: %s | ip: %s | image: %s",
			color.Yellow.Sprint(metadata["cluster"]),
			color.Yellow.Sprint(metadata["pod"]),
			color.Yellow.Sprint(metadata["namespace"]),
			color.Yellow.Sprint(metadata["ip"]),
			color.Yellow.Sprint(metadata["image"]),
		)
	case providers.Docker:
		header = fmt.Sprintf("container: %s | id: %s | image: %s",
			color.Yellow.Sprint(metadata["container"]),
			color.Yellow.Sprint(metadata["id"]),
			color.Yellow.Sprint(metadata["image"]),
		)
	case providers.Local:
		header = fmt.Sprintf("pid: %s",
			color.Yellow.Sprint(metadata["pid"]),
		)
	default:
		header = fmt.Sprintf("%+v", metadata)
	}

	fmt.Fprintln(out, "--------------------------------------------------------------------------------------------------------")
	fmt.Fprintf(out, " %s\n", header)
	fmt.Fprintln(out, "--------------------------------------------------------------------------------------------------------")
}
