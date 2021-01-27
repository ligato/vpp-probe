package cmd

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"go.ligato.io/vpp-probe/probe"
	"go.ligato.io/vpp-probe/providers"
	"go.ligato.io/vpp-probe/vpp/agent"
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

		agentInstances = append(agentInstances, vpp)

		if format := opts.Format; len(format) == 0 {
			printDiscoverTable(cli.Out(), vpp)
		} else {
			if err := formatAsTemplate(cli.Out(), format, vpp); err != nil {
				return err
			}
		}
	}

	return nil
}

func printDiscoverTable(out io.Writer, instance *agent.Instance) {
	printInstanceHeader(out, instance.Handler)

	w := prefixWriter(out, defaultPrefix)
	PrintInstance(w, instance)
}

func printInstanceHeader(out io.Writer, handler probe.Handler) {
	metadata := handler.Metadata()

	metaKey := func(k string) string {
		v := metadata[k]
		return fmt.Sprintf("%s: %v", k, instanceHeaderColor.Sprint(v))
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

func PrintInstance(out io.Writer, instance *agent.Instance) {
	var buf bytes.Buffer

	// info
	{
		fmt.Fprintf(&buf, "VPP version: %s\n", noteColor.Sprint(instance.Version))
	}
	fmt.Fprintln(&buf)

	// VPP interfaces
	fmt.Fprintln(&buf, headerColor.Sprint("VPP interfaces"))
	{
		w := prefixWriter(&buf, defaultPrefix)
		if len(instance.Config.VPP.Interfaces) > 0 {
			PrintVPPInterfacesTable(w, instance.Config)
		} else {
			fmt.Fprintln(w, nonAvailableColor.Sprint("No interfaces configured"))
		}
	}
	fmt.Fprintln(&buf)

	// Linux interfaces
	fmt.Fprintln(&buf, headerColor.Sprint("Linux interfaces"))
	{
		w := prefixWriter(&buf, defaultPrefix)
		if len(instance.Config.Linux.Interfaces) > 0 {
			PrintLinuxInterfacesTable(w, instance.Config)
		} else {
			fmt.Fprintln(w, nonAvailableColor.Sprint("No interfaces configured"))
		}
	}
	fmt.Fprintln(&buf)

	if _, err := buf.WriteTo(out); err != nil {
		logrus.Warnf("writing to output failed: %v", err)
	}
}
