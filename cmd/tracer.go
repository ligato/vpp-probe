package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"go.ligato.io/vpp-probe/cmd/tracer"
)

const traceExample = `  # Trace packets while running ping
  trace --env kube -q label=app=vpp -- ping 10.10.1.1

  # Trace packets for duration 3s
  trace --env kube -q label=app=vpp -d 5s`

func NewTracerCmd(glob *Flags) *cobra.Command {
	var (
		opts = DefaultTracerOptions
	)
	cmd := &cobra.Command{
		Use:     "tracer [flags] -- [command]",
		Aliases: []string{"trace"},
		Short:   "Trace packets from VPP instances",
		Long:    "Trace packets from selected VPP instances during execution of custom command (usually ping), or for a specified duration.",
		Example: traceExample,
		Args:    cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				opts.CustomCmd = strings.Join(args, " ")
			}
			return runTracer(*glob, opts)
		},
	}
	flags := cmd.Flags()
	flags.StringVar(&opts.ResultDir, "resultdir", opts.ResultDir, "Directory to store raw VPP trace results")
	flags.StringSliceVar(&opts.TraceNodes, "tracenodes", opts.TraceNodes, "List of traced nodes")
	flags.DurationVarP(&opts.TraceDur, "dur", "d", opts.TraceDur, "Duration of tracing (ignored when command is defined)")
	flags.UintVar(&opts.NumPackets, "numpackets", opts.NumPackets, "Number of packets to vpptrace per node")
	flags.BoolVar(&opts.PrintResult, "print", opts.PrintResult, "Print results from tracing to stdout")
	return cmd
}

type TracerOptions struct {
	TraceNodes  []string
	NumPackets  uint
	TraceDur    time.Duration
	CustomCmd   string
	ResultDir   string
	PrintResult bool
}

var DefaultTracerOptions = TracerOptions{
	ResultDir:   filepath.Join(os.TempDir(), "vppprobe-traces"),
	TraceDur:    time.Second * 5,
	TraceNodes:  tracer.DefaultNodes,
	NumPackets:  10000,
	PrintResult: false,
}

func runTracer(glob Flags, opts TracerOptions) error {
	ctl, err := SetupController(glob)
	if err != nil {
		return err
	}

	if err := ctl.DiscoverInstances(glob.Queries...); err != nil {
		return err
	}
	instances := ctl.Instances()

	logrus.Debugf("running tracer with %d instances", len(instances))

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

	logrus.Infof("tracing started for %d/%d instances", len(traceds), len(instances))

	if opts.CustomCmd != "" {
		cmd := exec.Command("sh", "-c", opts.CustomCmd)
		cmd.Stderr = os.Stderr
		cmd.Stdout = os.Stdout
		logrus.Infof("running command: %v", cmd)

		fmt.Fprintln(os.Stderr)
		if err := cmd.Run(); err != nil {
			logrus.Warnf("command failed: %v", err)
		}
		fmt.Fprintln(os.Stderr)
	} else {
		logrus.Infof("tracing for %v", opts.TraceDur)

		time.Sleep(opts.TraceDur)
	}

	logrus.Debugf("starting trace results collection")

	var done []*tracer.Traced
	for _, traced := range traceds {
		if err := traced.StopTracing(); err != nil {
			logrus.Warnf("stopping tracing for instance %v failed: %v", traced, err)
			continue
		}
		done = append(done, traced)
	}

	logrus.Infof("trace results retrieved from %d instances", len(done))

	for _, traced := range done {
		logrus.Infof("= instance %v", traced)

		result := traced.TraceResult()
		if result == nil {
			logrus.Infof("  traced: N/A")
			continue
		} else {
			logrus.Infof("  traced: %d packets", len(result.Packets))
		}

		if opts.ResultDir != "" {
			filename, err := tracer.SaveTraceData(opts.ResultDir, traced)
			if err != nil {
				logrus.Warnf("  saving trace data failed: %v", err)
			} else {
				logrus.Infof("  trace data saved to: %v", filename)
			}
		}

		if opts.PrintResult {
			tracer.PrintTraceResult(traced)
		}
	}

	return nil
}
