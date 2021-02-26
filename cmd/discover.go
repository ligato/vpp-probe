package cmd

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	"github.com/gookit/color"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"go.ligato.io/vpp-probe/probe"
	"go.ligato.io/vpp-probe/providers"
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
	return cmd
}

type DiscoverOptions struct {
	Format string
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

		if format := opts.Format; len(format) == 0 {
			printDiscoverTable(cli.Out(), instance)
		} else {
			if err := formatAsTemplate(cli.Out(), format, instance); err != nil {
				return err
			}
		}
	}

	return nil
}

func printDiscoverTable(out io.Writer, instance *vpp.Instance) {
	var buf bytes.Buffer

	printInstanceHeader(&buf, instance.Handler())

	w := prefixWriter(&buf, defaultPrefix)
	PrintInstance(w, instance)

	fmt.Fprint(out, color.ReplaceTag(buf.String()))
}

func printInstanceHeader(out io.Writer, handler probe.Handler) {
	metadata := handler.Metadata()

	metaKey := func(k string) string {
		v := metadata[k]
		return fmt.Sprintf("%s: %v", k, colorize(instanceHeaderColor, v))
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
			metaKey("image"),
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
	fmt.Fprintf(out, " %s\n", strings.Join(header, " | "))
	fmt.Fprintln(out, "----------------------------------------------------------------------------------------------------------------------------------")
}

func PrintInstance(out io.Writer, instance *vpp.Instance) {
	config := instance.Agent().Config

	// Info
	{
		fmt.Fprintf(out, "VPP version: %s\n", colorize(noteColor, instance.VersionInfo().Version))
	}
	fmt.Fprintln(out)

	// VPP
	{
		if len(config.VPP.Interfaces) > 0 {
			fmt.Fprintln(out, colorize(headerColor, "VPP"))
			w := prefixWriter(out, defaultPrefix)
			PrintVPPInterfacesTable(w, config)
		} else {
			fmt.Fprintln(out, colorize(nonAvailableColor, "No VPP interfaces configured"))
		}
	}
	fmt.Fprintln(out)

	// Linux
	{
		if len(config.Linux.Interfaces) > 0 {
			fmt.Fprintln(out, headerColor.Sprint("Linux"))
			w := prefixWriter(out, defaultPrefix)
			PrintLinuxInterfacesTable(w, config)
		} else {
			fmt.Fprintln(out, colorize(nonAvailableColor, "No linux interfaces configured"))
		}
	}
	fmt.Fprintln(out)
}
