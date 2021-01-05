package tracer

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gookit/color"
	"github.com/sirupsen/logrus"

	"go.ligato.io/vpp-probe/vpp"
	vpptrace "go.ligato.io/vpp-probe/vpp/trace"
)

var (
	DefaultNodes = vpptrace.CommonNodes
)

type Result = vpptrace.Result

type Traced struct {
	instance   *vpp.Instance
	traceNodes []string
	tracer     *vpptrace.Tracer
	result     *Result
	timestamp  time.Time
}

func NewTraced(instance *vpp.Instance, traceNodes []string, numPackets uint) (*Traced, error) {
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

func (t Traced) String() string {
	return fmt.Sprintf("%v", t.instance.ID())
}

func (t *Traced) StartTracing() error {
	if err := t.tracer.BeginTrace(t.traceNodes...); err != nil {
		return err
	}
	t.result = nil
	return nil
}

func (t *Traced) StopTracing() error {
	result, err := t.tracer.EndTrace()
	if err != nil {
		return err
	}
	t.result = result
	t.timestamp = time.Now()
	return nil
}

func (t *Traced) TraceResult() *Result {
	return t.result
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
		fmt.Sprintf(color.Yellow.Sprint("Packet")+" "+color.Blue.Sprint("%v"), fmt.Sprintf("%d", packet.ID)),
		fmt.Sprintf("⏲  "+color.Blue.Sprint("%v"), formatDurTimestamp(start)),
		fmt.Sprintf(getNodeColor(first.Name).Sprint("%s")+"  ￫  "+getNodeColor(last.Name).Sprint("%s"), first.Name, last.Name),
		fmt.Sprintf("took "+color.Blue.Sprint("%v"), took),
		fmt.Sprintf("nodes "+color.Blue.Sprint("%d"), len(packet.Captures)),
	}
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

func PrintTraceResult(traced *Traced) {
	result := traced.result
	logrus.Infof("= instance %v: traced %d packets", traced, len(result.Packets))
	for _, packet := range result.Packets {
		p := &packetNode{
			packet: packet,
		}
		var capture string
		for _, c := range packet.Captures {
			capture += fmt.Sprintf(" - %v\n%v", color.Yellow.Sprint(c.Name), prefixString(c.Content))
		}
		fmt.Fprintf(os.Stdout, "# %v\n%v", p, capture)
	}
}

func prefixString(s string) string {
	s = strings.TrimRight(s, "\n")
	lines := strings.Split(s, "\n")
	prefixed := strings.Join(lines, "\n\t")
	return fmt.Sprintf("\t%s\n", prefixed)
}

func SaveTraceData(traceDir string, traced *Traced) (string, error) {
	if err := os.MkdirAll(traceDir, 0777); err != nil {
		return "", err
	}

	filename := getResultFilename(traced)
	path := filepath.Join(traceDir, filename)

	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0777)
	if err != nil {
		return "", err
	}
	defer func() {
		if err := file.Close(); err != nil {
			logrus.Warnf("closing file failed: %v", err)
			return
		}
	}()

	host, _ := os.Hostname()

	// file header
	fmt.Fprintln(file, "# ========================================")
	fmt.Fprintln(file, "#  VPP TRACE DATA")
	fmt.Fprintln(file, "# ========================================")
	fmt.Fprintln(file, "#      Time:", traced.timestamp.Format(time.UnixDate))
	fmt.Fprintln(file, "#      Host:", host)
	fmt.Fprintln(file, "# ----------------------------------------")
	fmt.Fprintln(file, "#  Instance:", traced.instance.ID())
	fmt.Fprintln(file, "#   Version:", traced.instance.VersionInfo().Version)
	fmt.Fprintln(file, "#   Packets:", len(traced.result.Packets))
	fmt.Fprintln(file, "# ----------------------------------------")
	fmt.Fprintln(file)

	fmt.Fprint(file, traced.result.RawData)

	return file.Name(), nil
}

func getResultFilename(traced *Traced) string {
	t := traced.timestamp.Format("20060102T150405")
	s := getInstanceString(traced.instance)
	filename := fmt.Sprintf("vpptrace_%s_%s.txt", s, t)
	return strings.ToLower(filename)
}

func getInstanceString(instance *vpp.Instance) string {
	s := instance.ID()
	s = strings.ReplaceAll(s, " ", "-")
	s = strings.ReplaceAll(s, ":", "_")
	s = strings.ReplaceAll(s, "/", "~")
	return s
}
