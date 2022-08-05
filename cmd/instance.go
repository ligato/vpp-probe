package cmd

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/gookit/color"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"go.ligato.io/vpp-probe/vpp/agent"

	"go.ligato.io/vpp-probe/vpp"
)

const instancesExample = `  # List VPP instances in Kubernetes cluster
  vpp-probe instances -e kube

  # List VPP instances from multiple kubeconfig contexts in single run 
  vpp-probe instances -e kube --kubecontext="demo1,demo2"

  # List VPP instances in Docker containers
  vpp-probe instances -e docker

  # List local VPP instance
  vpp-probe instances -e local`

func NewInstancesCmd(cli Cli) *cobra.Command {
	var (
		opts InstancesOptions
	)
	cmd := &cobra.Command{
		Use:   "instances [options]",
		Short: "List running VPP instances",
		RunE: func(cmd *cobra.Command, args []string) error {
			return RunInstances(cli, opts)
		},
		Example: instancesExample,
	}
	flags := cmd.Flags()
	flags.StringVarP(&opts.Format, "format", "f", "", "Output format (json, yaml, go-template..)")
	return cmd
}

type InstancesOptions struct {
	Format   string
	IPsecAgg bool
}

func RunInstances(cli Cli, opts InstancesOptions) error {
	if err := cli.Client().DiscoverInstances(cli.Queries()...); err != nil {
		return err
	}

	instances := cli.Client().Instances()

	logrus.Debugf("discovered %d vpp instances", len(instances))

	if format := opts.Format; len(format) == 0 {
		printInstancesTable(cli.Out(), instances)
	} else {
		if err := formatAsTemplate(cli.Out(), format, instances); err != nil {
			return err
		}
	}

	return nil
}

func printInstancesTable(out io.Writer, instances []*vpp.Instance) {
	var buf bytes.Buffer
	w := tabwriter.NewWriter(&buf, 0, 1, 2, ' ', tabwriter.StripEscape|tabwriter.FilterHTML|tabwriter.DiscardEmptyColumns)

	header := []string{
		"Host", "Version", "Interfaces", "Agent", "TXs", "Uptime",
	}
	for i, h := range header {
		if h != "" {
			header[i] = colorize(color.Bold, h)
		}
	}
	fmt.Fprintln(w, strings.Join(header, "\t"))

	for _, instance := range instances {
		host := colorize(highlightColor, instance.Handler().ID())
		version := instance.VppInfo().Build.Version
		uptime := shortHumanDuration(time.Duration(instance.VppInfo().Runtime.Uptime) * time.Second)
		interfaces := formatVppInterfacesColumn(instance)
		agentInfo := formatAgentColumn(instance.Agent())
		txs := formatAgentTransactions(instance.Agent())

		cols := []string{
			host, version, interfaces, agentInfo, txs, uptime,
		}
		fmt.Fprintln(w, strings.Join(cols, "\t"))
	}

	if err := w.Flush(); err != nil {
		log.Println(err)
		return
	}

	fmt.Fprint(out, renderColor(buf.String()))
}

func formatAgentTransactions(instance *agent.Instance) string {

	return fmt.Sprint()
}

func formatVppInterfacesColumn(instance *vpp.Instance) string {
	var upNum, totalNum int
	for _, iface := range instance.VppInterfaces() {
		if iface.Index == 0 {
			// skip local0 interface
			continue
		}
		if iface.Status.Link {
			upNum++
		}
		totalNum++
	}
	count := fmt.Sprintf("%d/%d", upNum, totalNum)
	if totalNum == 0 {
		return count
	} else if upNum != totalNum {
		return colorize(color.Red, count)
	} else {
		return colorize(color.Green, count)
	}
}

func formatAgentColumn(agent *agent.Instance) string {
	if agent == nil {
		return "N/A"
	}

	return fmt.Sprintf("%v", agent.Info.Status.BuildVersion)
}
