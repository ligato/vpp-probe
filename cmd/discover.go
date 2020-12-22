package cmd

import (
	"fmt"
	"io"
	"os"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"go.ligato.io/vpp-probe/vpp/agent"
)

const discoverExample = `  # Discover VPP instances in Kubernetes pods with label "app=vpp""
  vpp-probe discover --env=kube --query "label=app=vpp"

  # Discover VPP instances in Docker container with name "vpp1"
  vpp-probe discover --env=docker --query  "name=vpp1"

  # Discover instances running locally
  vpp-probe discover`

func NewDiscoverCmd(glob *Flags) *cobra.Command {
	var (
		opts DiscoverOptions
	)
	cmd := &cobra.Command{
		Use:     "discover",
		Aliases: []string{"discovery"},
		Short:   "Discover running VPP instances",
		RunE: func(cmd *cobra.Command, args []string) error {
			return RunDiscover(*glob, opts)
		},
		Example: discoverExample,
	}
	flags := cmd.Flags()
	flags.BoolVar(&opts.PrintCLIs, "printclis", false, "Print output from CLI commands for each instance.")
	flags.StringSliceVar(&opts.ExtraCLIs, "extraclis", nil, "Additional CLI commands to run for each instance.")
	flags.StringVarP(&opts.Format, "format", "f", "", "Output format.")
	return cmd
}

type DiscoverOptions struct {
	ExtraCLIs []string
	PrintCLIs bool
	Format    string
}

func RunDiscover(glob Flags, opts DiscoverOptions) error {
	output := os.Stdout
	format := opts.Format

	ctl, err := SetupController(glob)
	if err != nil {
		return fmt.Errorf("provider setup error: %w", err)
	}

	if err := ctl.DiscoverInstances(glob.Queries...); err != nil {
		return err
	}

	instances := ctl.Instances()
	logrus.Infof("discovered %d vpp instances", len(instances))

	var agentInstances []*agent.Instance
	for _, instance := range instances {
		logrus.Debugf("- checking instance %+v: %v", instance.ID(), instance.Status())

		vpp, err := agent.NewInstance(instance.Probe())
		if err != nil {
			logrus.Errorf("instance %v error: %v", instance.ID(), err)
			continue
		}

		vpp.Version = instance.VersionInfo().Version
		if opts.PrintCLIs {
			agent.RunCLIs(vpp, opts.ExtraCLIs)
		}

		agentInstances = append(agentInstances, vpp)

		if len(format) == 0 {
			printDiscoverTable(output, vpp, opts.PrintCLIs)
		} else {
			if err := formatAsTemplate(output, format, vpp); err != nil {
				return err
			}
		}
	}

	return nil
}

func printDiscoverTable(output io.Writer, vpp *agent.Instance, printClis bool) {
	agent.PrintInstance(output, vpp)
	if printClis {
		agent.PrintCLIs(output, vpp)
	}
}
