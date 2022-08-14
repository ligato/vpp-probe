package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/gookit/color"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"go.ligato.io/vpp-probe/pkg/exec"
	"go.ligato.io/vpp-probe/pkg/strutil"
	"go.ligato.io/vpp-probe/vpp"
)

type ExecOptions struct {
	Format string
	Args   []string
}

func NewExecCmd(cli Cli) *cobra.Command {
	var (
		opts ExecOptions
	)
	cmd := &cobra.Command{
		Use:   "exec [options] command [command...]",
		Short: "Execute command on VPP instances",
		RunE: func(cmd *cobra.Command, args []string) error {
			logrus.Tracef("Run args: %+v", args)
			if len(args) == 0 {
				return fmt.Errorf("enter command to run")
			}
			opts.Args = args
			return RunExec(cli, opts)
		},
	}
	flags := cmd.Flags()
	flags.StringVarP(&opts.Format, "format", "f", "", "Output format (json, yaml, go-template..)")
	return cmd
}

func RunExec(cli Cli, opts ExecOptions) error {
	command := strings.Join(opts.Args, " ")

	logrus.Tracef("running exec (%+v) command: %q", opts, command)

	if err := cli.Client().DiscoverInstances(cli.Queries()...); err != nil {
		return err
	}
	instances := cli.Client().Instances()

	logrus.Debugf("running exec for %d instances", len(instances))

	// TODO: run in parallel, possibly with configurable throttle
	for _, instance := range instances {
		logrus.Debugf("executing command on instance %v", instance.ID())

		executed, err := executeCommands(instance.Handler(), []string{command})
		if err != nil {
			logrus.Errorf("exec on instance %v failed: %v", instance.ID(), err)
			continue
		}

		execInstance := &ExecInstance{
			Instance: instance,
			Commands: executed,
		}

		if opts.Format == "" {
			printExecInstance(cli.Out(), execInstance)
		} else {
			if err := formatAsTemplate(cli.Out(), opts.Format, execInstance); err != nil {
				return err
			}
		}
	}

	return nil
}

func printExecInstance(out io.Writer, instance *ExecInstance) {
	var buf bytes.Buffer

	printInstanceHeader(&buf, instance.Instance.Handler())
	fmt.Fprintln(&buf)

	printExecutedCommands(strutil.IndentedWriter(&buf), instance.Commands)

	fmt.Fprint(out, renderColor(buf.String()))
}

func printExecutedCommands(out io.Writer, commands []ExecutedCommand) {
	for _, cmd := range commands {
		fmt.Fprintf(out, "# %s (took %v)\n\n", colorize(color.Yellow, cmd.Command), cmd.Took)
		fmt.Fprintln(strutil.IndentedWriter(out), cmd.Output)
	}
}

type ExecInstance struct {
	Instance *vpp.Instance
	Commands []ExecutedCommand
}

type ExecutedCommand struct {
	Command string
	Output  CommandOutput
	Started time.Time
	Took    time.Duration
}

type CommandOutput string

func (e CommandOutput) String() string {
	return color.Render(string(e))
}

func (e CommandOutput) MarshalJSON() ([]byte, error) {
	lines := []string{}
	str := color.ClearCode(string(e))
	lines = strings.Split(str, "\n")
	return json.Marshal(lines)
}

func (e *CommandOutput) UnmarshalJSON(b []byte) error {
	lines := []string{}
	if err := json.Unmarshal(b, &lines); err != nil {
		return err
	}
	*e = CommandOutput(strings.Join(lines, "\n"))
	return nil
}

func executeCommands(exec exec.Interface, commands []string) ([]ExecutedCommand, error) {
	var executed []ExecutedCommand

	for _, cmd := range commands {
		start := time.Now()
		out, err := execCommand(exec, cmd)
		if err != nil {
			logrus.Warnf("exec command %q error: %v", cmd, err)
			return nil, err
		}
		executed = append(executed, ExecutedCommand{
			Command: cmd,
			Output:  CommandOutput(out),
			Started: start,
			Took:    time.Since(start),
		})
	}

	return executed, nil
}

func execCommand(exec exec.Interface, cmd string) (string, error) {
	b, err := exec.Command(cmd).Output()
	if err != nil {
		return "", err
	}
	out := string(b)
	out = strings.ReplaceAll(out, "\r\r\n", "\n")
	out = strings.ReplaceAll(out, "\r\n", "\n")
	return out, nil
}
