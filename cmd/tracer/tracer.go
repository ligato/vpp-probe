package tracer

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gookit/color"
	"github.com/segmentio/textio"
	"github.com/sirupsen/logrus"

	"go.ligato.io/vpp-probe/vpp"
	vpptrace "go.ligato.io/vpp-probe/vpp/trace"
)

// TODO: merge this package with vpp/trace

var (
	DefaultNodes = vpptrace.CommonNodes
)

type Result = vpptrace.Result

type Packet vpptrace.Packet

// Start returns the elapsed time since boot until the first capture.
func (p *Packet) Start() time.Duration {
	if first := p.FirstCapture(); first != nil {
		return first.Start
	}
	return 0
}

// FirstCapture returns the first capture of the packet
// or nil if packet has no captures.
func (p *Packet) FirstCapture() *vpptrace.Capture {
	if len(p.Captures) == 0 {
		return nil
	}
	return &p.Captures[0]
}

// LastCapture returns the last capture of the packet
// or nil if packet has no captures.
func (p *Packet) LastCapture() *vpptrace.Capture {
	if len(p.Captures) == 0 {
		return nil
	}
	return &p.Captures[len(p.Captures)-1]
}

type Traced struct {
	Instance   *vpp.Instance
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
		Instance:   instance,
		traceNodes: traceNodes,
		tracer:     tracer,
		result:     nil,
	}
	return traced, nil
}

func (t Traced) String() string {
	return fmt.Sprintf("%v", t.Instance.ID())
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
	packet Packet
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
		fmt.Sprint(color.Yellow.Sprint("Packet") + " " + color.Blue.Sprint(packet.ID)),
		fmt.Sprint("⏲  " + color.Blue.Sprint(formatDurTimestamp(start))),
		fmt.Sprint(getNodeColor(first.Name).Sprint(first.Name) + "  ￫  " + getNodeColor(last.Name).Sprint(last.Name)),
		fmt.Sprint("took " + color.Blue.Sprint(took)),
		fmt.Sprint("nodes " + color.Blue.Sprint(len(packet.Captures))),
	}
	return strings.Join(pktFields, " | ")
}

type captureNode struct {
	capture vpptrace.Capture
}

func (c *captureNode) String() string {
	cptFields := []string{
		color.Cyan.Sprint(c.capture.Name),
	}
	if c.capture.Start > 0 {
		cptFields = append(cptFields, "⏲  "+color.Blue.Sprint(c.capture.Start))
	}
	return strings.Join(cptFields, " | ")
}

func PrintTraceResult(w io.Writer, traced *Traced) {
	result := traced.result

	fmt.Fprintf(w, "%d packets traced\n", len(result.Packets))
	fmt.Fprintln(w)

	for _, packet := range result.Packets {
		p := &packetNode{
			packet: Packet(packet),
		}
		var buf bytes.Buffer
		fmt.Fprintf(&buf, "# %v", p)
		fmt.Fprintln(&buf)
		pw := textio.NewPrefixWriter(&buf, "  ")
		for _, c := range packet.Captures {
			var cinfo string
			if d := c.Start - p.packet.Start(); d > 0 {
				cinfo = fmt.Sprintf(" (+%v)", d)
			}
			fmt.Fprintf(pw, "- %v\n%v", color.Yellow.Sprint(c.Name)+cinfo, prefixString(c.Content, "\t"))
		}
		fmt.Fprintln(w, buf.String())
	}
}

func formatDurTimestamp(dur time.Duration) string {
	var t time.Time
	t = t.Add(dur)
	return t.Format("15:04:05.00000")
}

func prefixString(s, prefix string) string {
	s = strings.TrimRight(s, "\n")
	lines := strings.Split(s, "\n")
	prefixed := strings.Join(lines, "\n"+prefix)
	return fmt.Sprintf(prefix+"%s\n", prefixed)
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
	fmt.Fprintln(file, "#  Instance:", traced.Instance.ID())
	fmt.Fprintln(file, "#   Version:", traced.Instance.VppInfo().Build.Version)
	fmt.Fprintln(file, "#   Packets:", len(traced.result.Packets))
	fmt.Fprintln(file, "# ----------------------------------------")
	fmt.Fprintln(file)

	fmt.Fprint(file, traced.result.RawData)

	return file.Name(), nil
}

func getResultFilename(traced *Traced) string {
	t := traced.timestamp.Format("20060102T150405")
	s := getInstanceString(traced.Instance)
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
