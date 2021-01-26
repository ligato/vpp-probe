package cmd

import (
	"bytes"
	"fmt"
	"io"
	"strings"

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

func NewDiscoverCmd(cli Cli) *cobra.Command {
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

func RunDiscover(cli Cli, opts DiscoverOptions) error {
	if err := cli.Client().DiscoverInstances(cli.Queries()...); err != nil {
		return err
	}

	instances := cli.Client().Instances()
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

	var buf bytes.Buffer
	PrintInstance(&buf, instance)
	fmt.Fprint(out, prefixString(buf.String(), "  "))

	if printClis {
		PrintCLIs(out, instance)
	}
}

func printInstanceHeader(out io.Writer, instance *agent.Instance) {
	metadata := instance.Handler.Metadata()

	metaKey := func(k string) string {
		v := metadata[k]
		return fmt.Sprintf("%s: %v", k, color.Yellow.Sprint(v))
	}

	var header []string

	switch metadata["env"] {
	case providers.Kube:
		header = []string{
			metaKey("pod"),
			metaKey("namespace"),
			metaKey("node"),
			metaKey("cluster"),
			metaKey("ip"),
		}
	case providers.Docker:
		header = []string{
			metaKey("container"),
			metaKey("id"),
		}
	case providers.Local:
		header = []string{
			metaKey("pid"),
			metaKey("id"),
		}
	default:
		for k := range metadata {
			header = append(header, metaKey(k))
		}
	}

	fmt.Fprintln(out, "----------------------------------------------------------------------------------------------------------------------------------")
	fmt.Fprintln(out, strings.Join(header, " | "))
	fmt.Fprintln(out, "----------------------------------------------------------------------------------------------------------------------------------")
}

func PrintCLIs(out io.Writer, instance *agent.Instance) {
	for k, v := range instance.CliData {
		val := color.FgLightBlue.Sprint(v)
		val = "\t" + strings.ReplaceAll(val, "\n", "\n\t")
		fmt.Fprintf(out, "%s:\n\n%s\n", k, val)
		fmt.Fprintln(out)
	}
	fmt.Fprintln(out)
}
