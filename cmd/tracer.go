package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/gookit/color"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"go.ligato.io/vpp-probe/vpp"
	vpptrace "go.ligato.io/vpp-probe/vpp/trace"
)

var DefaultTracerOptions = TracerOptions{
	ResultDir:  os.TempDir(),
	TraceDur:   time.Second * 5,
	TraceNodes: vpptrace.CommonNodes,
	NumPackets: 10000,
}

func NewTracerCmd(glob *Flags) *cobra.Command {
	var (
		opts = DefaultTracerOptions
	)
	cmd := &cobra.Command{
		Use:     "tracer",
		Short:   "Trace packets from VPP instances",
		Aliases: []string{"trace"},
		Args:    cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTracer(*glob, opts)
		},
	}
	flags := cmd.Flags()
	flags.StringVar(&opts.ResultDir, "resultdir", opts.ResultDir, "Directory to store raw VPP trace results")
	flags.StringSliceVar(&opts.TraceNodes, "tracenodes", opts.TraceNodes, "List of traced nodes")
	flags.DurationVarP(&opts.TraceDur, "tracedur", "d", opts.TraceDur, "Duration of tracing")
	flags.StringVar(&opts.CustomCmd, "cmd", opts.CustomCmd, "Custom command to run during tracing")
	flags.UintVar(&opts.NumPackets, "numpackets", opts.NumPackets, "Number of packets to vpptrace per node")
	return cmd
}

type TracerOptions struct {
	TraceNodes []string
	NumPackets uint
	TraceDur   time.Duration
	CustomCmd  string
	ResultDir  string
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
	logrus.Debugf("discovered %d vpp instances", len(instances))

	var traceds []*Traced
	for _, instance := range instances {
		logrus.Debugf("- instance: %+v", instance.ID())
		traced, err := newTraced(instance, opts.TraceNodes, opts.NumPackets)
		if err != nil {
			logrus.Warnf("tracer error: %v", err)
			continue
		}
		if err := traced.startTracing(); err != nil {
			logrus.Warnf("tracing packets for instance %v failed: %v", traced, err)
			continue
		}
		traceds = append(traceds, traced)
	}

	logrus.Debugf("tracing started for %d/%d instances", len(traceds), len(instances))

	if opts.CustomCmd != "" {
		cmd := exec.Command("sh", "-c", opts.CustomCmd)

		logrus.Infof("running custom command: %q", cmd)
		time.Sleep(time.Second)

		out, err := cmd.Output()
		logrus.Infof("command output: %s", out)
		if err != nil {
			logrus.Warnf("running custom command %q failed: %v", cmd, err)
		}
	} else {
		logrus.Infof("sleeping for %v to trace packets", opts.TraceDur)
		time.Sleep(opts.TraceDur)
	}

	logrus.Debugf("tracing complete, starting trace results collection..")

	var results []*vpptrace.Result
	for _, traced := range traceds {
		if err := traced.stopTracing(); err != nil {
			logrus.Warnf("stopping tracing for instance %v failed: %v", traced, err)
			continue
		}
		if opts.ResultDir != "" {
			saveTraceData(opts.ResultDir, traced.instance, traced.result)
		}
		results = append(results, traced.result)
	}

	logrus.Debugf("collected %d trace results", len(results))

	for _, traced := range traceds {
		if traced.result == nil {
			continue
		}
		result := traced.result
		logrus.Infof("= instance %v: traced %d packets:", traced, len(result.Packets))
		for _, packet := range result.Packets {
			p := &packetNode{
				packet: packet,
			}
			var capture string
			for _, c := range packet.Captures {
				capture += fmt.Sprintf(" >>> %v\n%v\n", color.Yellow.Sprint(c.Name), c.Content)
			}
			logrus.Infof("  - %v\n%v", p, capture)
		}
	}

	return nil
}

func saveTraceData(traceDir string, instance *vpp.Instance, trace *vpptrace.Result) {
	timestamp := time.Now()
	host, _ := os.Hostname()

	t := timestamp.Format("2015-Jan-25_11:06:39")
	s := instance.ID()
	s = strings.ReplaceAll(s, " ", "-")
	s = strings.ReplaceAll(s, ":", "_")
	name := fmt.Sprintf("vpptrace_%s_%s_%d-pkts.txt", strings.ToLower(s), t, len(trace.Packets))

	path := filepath.Join(traceDir, name)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE, 0655)
	if err != nil {
		logrus.Warnf("failed to save trace data to %s: %v", path, err)
		return
	}
	defer file.Close()

	logrus.Infof("storing trace results to %q", file.Name())

	fmt.Fprintln(file, "# ========================================")
	fmt.Fprintln(file, "#  VPP PACKET TRACE")
	fmt.Fprintln(file, "# ========================================")
	fmt.Fprintln(file, "#      Time:", timestamp.Format(time.UnixDate))
	fmt.Fprintln(file, "#      Host:", host)
	fmt.Fprintln(file, "# ----------------------------------------")
	fmt.Fprintln(file, "#  Instance:", instance.ID())
	fmt.Fprintln(file, "#   Version:", instance.VersionInfo().Version)
	fmt.Fprintln(file, "# ----------------------------------------")
	fmt.Fprintln(file)
	fmt.Fprint(file, trace.RawData)
}

type Traced struct {
	instance   *vpp.Instance
	traceNodes []string
	tracer     *vpptrace.Tracer
	result     *vpptrace.Result
}

func (t Traced) String() string {
	return fmt.Sprintf("%v", t.instance.ID())
}

func newTraced(instance *vpp.Instance, traceNodes []string, numPackets uint) (*Traced, error) {
	tracer, err := vpptrace.NewTracer(instance)
	if err != nil {
		return nil, err
	}
	tracer.SetNumPackets(int(numPackets))

	traced := &Traced{
		instance:   instance,
		traceNodes: traceNodes,
		tracer:     tracer,
		result:     nil,
	}
	return traced, nil
}

func (t *Traced) startTracing() error {
	// TODO: select specific nodes
	if err := t.tracer.BeginTrace(t.traceNodes...); err != nil {
		return err
	}
	t.result = nil
	return nil
}

func (t *Traced) stopTracing() error {
	result, err := t.tracer.EndTrace()
	if err != nil {
		return err
	}
	t.result = result
	return nil
}

type packetNode struct {
	packet vpptrace.Packet
}

func (c *packetNode) String() string {
	packet := c.packet
	start := packet.FirstCapture().Start
	took := packet.LastCapture().Start - start
	if start > time.Second*10 {
		start = start.Round(time.Millisecond)
	}
	first := packet.FirstCapture()
	last := packet.LastCapture()

	getNodeColor := func(n string) color.Color {
		switch n {
		case "drop":
			return color.Red
		default:
			return color.Magenta
		}
	}
	pktFields := []string{
		fmt.Sprintf(color.Bold.Sprint("Packet")+" "+color.Blue.Sprint("%4v"), fmt.Sprintf("%03d", packet.ID)),
		fmt.Sprintf("nodes "+color.Blue.Sprint("%2d"), len(packet.Captures)),
		fmt.Sprintf("took "+color.Blue.Sprint("%9v"), took),
		fmt.Sprintf(getNodeColor(first.Name).Sprint("%20s")+"  ￫  "+getNodeColor(last.Name).Sprint("%s"), first.Name, last.Name),
	}
	pktFields = append(pktFields, fmt.Sprintf("⏲  "+color.Blue.Sprint("%v"), formatDurTimestamp(start)))
	return strings.Join(pktFields, " | ")
}

type captureNode struct {
	capture vpptrace.Capture
}

func (c *captureNode) String() string {
	cptFields := []string{
		color.Cyan.Sprintf("%s", c.capture.Name),
	}
	if c.capture.Start > 0 {
		cptFields = append(cptFields, fmt.Sprintf("⏲  "+color.Blue.Sprint("%v"), c.capture.Start))
	}
	return strings.Join(cptFields, " | ")
}

func formatDurTimestamp(dur time.Duration) string {
	var t time.Time
	t = t.Add(dur)
	return t.Format("15:04:05.00000")
}
