package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/gookit/color"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"go.ligato.io/vpp-probe/probe"
)

var DefaultExecCommands = []string{
	"vppctl show interface",
	"vppctl show err",
}

func NewExecCmd(cli Cli) *cobra.Command {
	var (
		opts ExecOptions
	)
	cmd := &cobra.Command{
		Use:   "exec [options] command [command...]",
		Short: "Execute command on VPP instances",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				opts.Commands = args
			} else {
				opts.Commands = DefaultExecCommands
			}
			return RunExec(cli, opts)
		},
	}
	flags := cmd.Flags()
	flags.StringVarP(&opts.Format, "format", "f", "", "Output format (json, yaml, go-template..)")
	return cmd
}

type ExecOptions struct {
	Format   string
	Commands []string
}

func RunExec(cli Cli, opts ExecOptions) error {
	if err := cli.Client().DiscoverInstances(cli.Queries()...); err != nil {
		return err
	}
	instances := cli.Client().Instances()

	logrus.Debugf("running exec for %d instances", len(instances))

	for _, instance := range instances {
		logrus.Debugf("executing %d commands on instance %v", len(opts.Commands), instance.ID())

		clidata, err := runCommands(instance.Handler(), opts.Commands)
		if err != nil {
			logrus.Warnf("exec on instance %v failed: %v", instance, err)
			continue
		}

		printInstanceHeader(cli.Out(), instance.Handler())
		fmt.Fprintln(cli.Out())

		w := prefixWriter(cli.Out(), defaultPrefix)
		printCliData(w, clidata, opts.Commands)
	}

	return nil
}

type CLIData map[string]string

func (e CLIData) MarshalJSON() ([]byte, error) {
	clis := map[string][]string{}
	for k, v := range e {
		clis[k] = strings.Split(v, "\n")
	}
	return json.Marshal(clis)
}

func runCommands(h probe.Handler, commands []string) (CLIData, error) {
	clidata := CLIData{}

	for _, cmd := range commands {
		out, err := execCommand(h, cmd)
		if err != nil {
			logrus.Debugf("exec command %q error: %v", cmd, err)
			return nil, err
		}
		clidata[cmd] = out
	}

	return clidata, nil
}

func execCommand(handler probe.Handler, cmd string) (string, error) {
	b, err := handler.Command(cmd).Output()
	if err != nil {
		return "", err
	}
	out := string(b)
	out = strings.ReplaceAll(out, "\r\r\n", "\n")
	out = strings.ReplaceAll(out, "\r\n", "\n")
	return out, nil
}

func printCliData(out io.Writer, clidata map[string]string, keys []string) {
	for _, k := range keys {
		v := clidata[k]
		fmt.Fprintf(out, "# %s\n\n", color.Yellow.Sprint(k))
		fmt.Fprintln(prefixWriter(out, defaultPrefix), v)
	}
}
