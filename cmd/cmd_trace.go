package cmd

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/gookit/color"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"go.ligato.io/vpp-probe/cmd/tracer"
	"go.ligato.io/vpp-probe/pkg/strutil"
)

const traceExample = `  # Trace packets while running ping
  trace --env kube -- ping 10.10.1.1

  # Trace packets for duration 10s
  trace --env kube -- sleep 10`

type TraceOptions struct {
	TraceNodes  []string
	NumPackets  uint
	CustomCmd   string
	ResultDir   string
	PrintResult bool
}

var DefaultTraceOptions = TraceOptions{
	ResultDir:   filepath.Join(os.TempDir(), "vppprobe-traces"),
	TraceNodes:  tracer.DefaultNodes,
	NumPackets:  10000,
	PrintResult: false,
}

func NewTraceCmd(cli Cli) *cobra.Command {
	var (
		opts = DefaultTraceOptions
	)
	cmd := &cobra.Command{
		Use:     "trace [flags] -- [command]",
		Short:   "Trace packets from VPP instances",
		Long:    "Trace packets from VPP instances while executing a command (defaults to 'sleep 5')",
		Example: traceExample,
		Args:    cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				opts.CustomCmd = "sleep 5"
			} else {
				opts.CustomCmd = strings.Join(args, " ")
			}
			return RunTrace(cli, opts)
		},
	}
	flags := cmd.Flags()
	flags.StringVar(&opts.ResultDir, "resultdir", opts.ResultDir, "Directory to store raw VPP trace results")
	flags.StringSliceVar(&opts.TraceNodes, "tracenodes", opts.TraceNodes, "List of traced nodes")
	flags.UintVar(&opts.NumPackets, "numpackets", opts.NumPackets, "Number of packets to vpptrace per node")
	flags.BoolVar(&opts.PrintResult, "print", opts.PrintResult, "Print results from tracing to stdout")
	return cmd
}

func RunTrace(cli Cli, opts TraceOptions) error {
	if err := cli.Client().DiscoverInstances(cli.Queries()...); err != nil {
		return err
	}
	instances := cli.Client().Instances()

	logrus.Debugf("running trace with %d instances", len(instances))

	var traceds []*tracer.Traced
	for _, instance := range instances {
		logrus.Debugf("- instance: %+v", instance.ID())

		traced, err := tracer.NewTraced(instance, opts.TraceNodes, opts.NumPackets)
		if err != nil {
			logrus.Warnf("tracer error: %v", err)
			continue
		}
		if err := traced.StartTracing(); err != nil {
			logrus.Warnf("tracing packets for instance %v failed: %v", traced, err)
			continue
		}
		traceds = append(traceds, traced)
	}

	if len(traceds) == 0 {
		return fmt.Errorf("failed to start trace for instances")
	}
	logrus.Infof("tracing started for %d/%d instances", len(traceds), len(instances))

	var commandErr error
	cmd := exec.Command("sh", "-c", opts.CustomCmd)
	cmd.Stderr = cli.Err()
	cmd.Stdout = cli.Out()
	logrus.Infof("running command: %v", cmd)

	fmt.Fprintln(cli.Err())
	if commandErr = cmd.Run(); commandErr != nil {
		logrus.Warnf("command failed: %v", commandErr)
	}
	fmt.Fprintln(cli.Err())

	logrus.Debugf("starting trace results collection")

	var done []*tracer.Traced
	for _, traced := range traceds {
		if err := traced.StopTracing(); err != nil {
			logrus.Warnf("stopping tracing for instance %v failed: %v", traced, err)
			continue
		}
		done = append(done, traced)
	}

	logrus.Debugf("trace results collected from %d instances", len(done))

	for _, traced := range done {
		result := traced.TraceResult()
		if result == nil || len(result.Packets) == 0 {
			logrus.Infof("- %v:\t %v", color.Gray.Sprint(traced), color.FgDarkGray.Sprint("N/A"))
			continue
		} else {
			logrus.Infof("+ %v:\t%v packets", color.Yellow.Sprint(traced), color.Cyan.Sprintf("%4d", len(result.Packets)))

		}
		if opts.ResultDir != "" {
			filename, err := tracer.SaveTraceData(opts.ResultDir, traced)
			if err != nil {
				logrus.Warnf("  saving trace data failed: %v", err)
			} else {
				logrus.Debugf("  trace data saved to: %v", filename)
			}
		}
	}

	if opts.PrintResult {
		fmt.Fprintf(cli.Err(), "\n\tPress any key to print trace results\n")
		fmt.Fscanf(cli.In(), "%c")

		for _, traced := range done {
			result := traced.TraceResult()
			if result == nil {
				continue
			}

			var buf bytes.Buffer

			printInstanceHeader(&buf, traced.Instance.Handler())

			tracer.PrintTraceResult(strutil.IndentedWriter(&buf), traced)

			fmt.Fprint(cli.Out(), renderColor(buf.String()))
		}
	} else {

	}

	return commandErr
}
