//  Copyright (c) 2020 Cisco and/or its affiliates.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at:
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	ui "github.com/gizak/termui/v3"
	"github.com/gizak/termui/v3/widgets"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"go.ligato.io/vpp-probe/internal/vpptrace"
	"go.ligato.io/vpp-probe/pkg/kube"
)

func init() {
	rootCmd.AddCommand(tracerCmd)

	tracerCmd.Flags().StringVar(&kubeconfig, "kubeconfig", "", "Path to kubeconfig")
	tracerCmd.Flags().StringVar(&TraceDir, "tracedir", os.TempDir(), "Directory to store raw trace data")
	tracerCmd.Flags().StringSliceVar(&TraceNodes, "tracenodes", TraceNodes, "List of traced nodes")
	tracerCmd.Flags().DurationVarP(&TraceTime, "tracedur", "d", TraceTime, "Duration of tracing")
	tracerCmd.Flags().UintVar(&NumPackets, "numpackets", NumPackets, "Number of packets to trace per node")
	//tracerCmd.Flags().StringVarP(&TraceTarget, "target", "t", "", "Target to trace")
}

var tracerCmd = &cobra.Command{
	Use:   "tracer",
	Short: "Collect and analyze packet traces from VPP instances",
	Args:  cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runTracer(args)
	},
}

var (
	kubeconfig string
	TraceDir   string
	TraceTime       = time.Second * 5
	TraceNodes      = vpptrace.ALL
	NumPackets uint = 10000
	//TraceTarget string
)

func runTracer(args []string) error {
	config := kubeconfig
	kubectx, err := kube.NewKubeCtx(config)
	if err != nil {
		return fmt.Errorf("loading kubeconfig %s failed: %v", config, err)
	}

	clusterName := kubectx.Contexts[kubectx.CurrentContext].Cluster
	queries := parseQueries(args)
	if len(queries) == 0 {
		return fmt.Errorf("at least one query neeeded")
	}

	instances, err := discoverVppInstances(kubectx, queries)
	if err != nil {
		return fmt.Errorf("cluster %v failed: %v", clusterName, err)
	}

	if len(instances) == 0 {
		return fmt.Errorf("no VPP instances found")
	}

	logrus.Infof("found %d VPP instances, initializing tracer..", len(instances))

	//var traceIdx int
	/*if TraceTarget != "" {
		ifaces := dumpInterfaces(ch)
		for _, iface := range ifaces {
			target := strings.ToLower(TraceTarget)
			if iface.Name == target || strings.ToLower(iface.Tag) == target {
				traceIdx = int(iface.Index)
			}
		}
		if traceIdx == 0 {
			logrus.Fatalf("target interface %q not found", TraceTarget)
		}
	}
	if traceIdx > 0 {
		for _, packet := range trace.Packets {
			// fmt.Printf("Packet %v:\n", packet.ID)
			var include bool
			for _, capture := range packet.Captures {
				content := strings.TrimSuffix(capture.Content, "\n")
				content = strings.ReplaceAll(content, "\n", "\n\t")
				if strings.Contains(content, fmt.Sprintf("if_index %d", traceIdx)) {
					include = true
					break
				}
				// fmt.Printf(" -> %v:\n\t%s\n", capture.Name, content)

			}
			if include {
				packets = append(packets, packet)
			}
		}
	}*/

	initTracer(instances)

	return nil
}

func tracePackets(instance *VppInstance, dur time.Duration) (*vpptrace.Traces, error) {
	tracer, err := vpptrace.NewTracer(instance)
	if err != nil {
		return nil, err
	}
	// TODO: select specific nodes
	/*vpptrace.VIRTIO_INPUT,
	vpptrace.SESSION_QUEUE,
	vpptrace.AF_PACKET_INPUT,
	vpptrace.MEMIF_INPUT,*/
	err = tracer.BeginTrace(TraceNodes...)
	if err != nil {
		return nil, err
	}

	logrus.Debugf("tracing packets for %v..", dur)
	time.Sleep(dur)

	trace, err := tracer.EndTrace()
	if err != nil {
		return nil, err
	}
	if TraceDir != "" {
		saveTraceData(TraceDir, instance, trace)
	}
	return trace, nil
}

func saveTraceData(dir string, instance *VppInstance, trace *vpptrace.Traces) {
	t := time.Now()

	s := strings.ReplaceAll(instance.String(), " ", "-")
	name := fmt.Sprintf("vpptrace_%s_%s_%dpkts.txt", strings.ToLower(s), t.Format("20150225_110639"), len(trace.Packets))

	file, err := os.OpenFile(filepath.Join(dir, name), os.O_WRONLY|os.O_CREATE, 0655)
	if err != nil {
		logrus.Warnf("failed to save trace data to dir %s: %v", TraceDir, err)
		return
	}
	defer file.Close()

	fmt.Fprintln(file, "# ========================================")
	fmt.Fprintln(file, "#  VPP PACKET TRACE")
	fmt.Fprintln(file, "# ========================================")
	fmt.Fprintln(file, "#      Time:", t.Format(time.UnixDate))
	fmt.Fprintln(file, "#      Host:", os.Getenv("HOSTNAME"))
	fmt.Fprintln(file, "# ----------------------------------------")
	fmt.Fprintln(file, "#  Instance:", instance.String())
	fmt.Fprintln(file, "#   Version:", instance.Version)
	fmt.Fprintln(file, "# ----------------------------------------")
	fmt.Fprintln(file)
	fmt.Fprint(file, trace.RawTrace)
}

func buildTreeNodes(packets []vpptrace.Packet) []*widgets.TreeNode {
	var nodes []*widgets.TreeNode
	for _, packet := range packets {
		var captures []*widgets.TreeNode
		for _, capture := range packet.Captures {
			content := strings.TrimSuffix(capture.Content, "\n")
			cNode := &widgets.TreeNode{
				Nodes: []*widgets.TreeNode{},
			}
			cNode.Value = &captureNode{
				node:    cNode,
				capture: capture,
			}
			contentLines := strings.Split(content, "\n")
			for _, line := range contentLines {
				cNode.Nodes = append(cNode.Nodes, &widgets.TreeNode{
					Value: bytes.NewBufferString(line),
				})
			}
			captures = append(captures, cNode)
		}
		pNode := &widgets.TreeNode{
			Nodes: captures,
		}
		pNode.Value = &packetNode{
			node:   pNode,
			packet: packet,
		}
		nodes = append(nodes, pNode)
	}
	return nodes
}

func initTracer(instances []*VppInstance) {
	if err := ui.Init(); err != nil {
		log.Fatalf("failed to initialize termui: %v", err)
	}
	defer ui.Close()

	toolbar := widgets.NewParagraph()
	toolbar.Title = "[ VPP Packet Tracer ]"
	toolbar.TitleStyle = ui.NewStyle(ui.ColorBlue + 11)
	for _, instance := range instances {
		ver := instance.Version
		if parts := strings.Fields(instance.Version); len(parts) > 3 {
			ver = parts[1]
		}
		toolbar.Text += fmt.Sprintf(" -> [%v](fg:yellow) | %s\n", instance, ver)
	}

	packetTree := widgets.NewTree()
	packetTree.Title = "[ Packets ]"
	packetTree.TitleStyle = ui.NewStyle(ui.ColorBlue + 11)
	packetTree.SelectedRowStyle = ui.NewStyle(ui.ColorClear, ui.ColorClear, ui.ModifierReverse)
	packetTree.WrapText = true
	packetTree.PaddingLeft = 1
	packetTree.BorderStyle = ui.NewStyle(ui.ColorClear, ui.ColorClear)

	label := func(instance *VppInstance) string {
		return fmt.Sprintf("[%v](fg:cyan)", instance)
	}

	var nodes []*widgets.TreeNode
	for _, instance := range instances {
		nodes = append(nodes, &widgets.TreeNode{Value: bytes.NewBufferString(label(instance))})
	}
	packetTree.SetNodes(nodes)

	logs := widgets.NewParagraph()
	logs.Title = "Logs"
	logs.PaddingLeft = 1

	logrus.SetFormatter(&logrus.TextFormatter{
		DisableColors: true,
	})
	logrus.SetOutput(writeLogsTo(logs))

	grid := ui.NewGrid()
	termWidth, termHeight := ui.TerminalDimensions()
	grid.SetRect(0, 0, termWidth, termHeight)
	grid.Set(
		ui.NewRow(.1,
			ui.NewCol(1.0, toolbar),
		),
		ui.NewRow(.7,
			ui.NewCol(1.0, packetTree),
		),
		ui.NewRow(.2,
			ui.NewCol(1.0, logs),
		),
	)

	hintBar := widgets.NewParagraph()
	hintBar.TextStyle = ui.NewStyle(ui.ColorClear, ui.ColorClear, ui.ModifierClear)
	hintBar.Border = false
	hintStyle := "fg:black,bg:white,mod:bold"
	hintFields := []string{
		fmt.Sprintf("[<T>](%[1]s) start trace", hintStyle),
		fmt.Sprintf("[<h>](%[1]s) hide drops", hintStyle),
		fmt.Sprintf("[<Up>](%[1]s)/[<Down>](%[1]s) move", hintStyle),
		fmt.Sprintf("[<Home>](%[1]s)/[<End>](%[1]s) scroll", hintStyle),
		fmt.Sprintf("[<Enter>](%[1]s) toggle", hintStyle),
		fmt.Sprintf("[<e>](%[1]s)/[<E>](%[1]s) expand", hintStyle),
		fmt.Sprintf("[<c>](%[1]s)/[<C>](%[1]s) collapse", hintStyle),
		fmt.Sprintf("[<q>](%[1]s) quit", hintStyle),
	}
	hintBar.Text = " " + strings.Join(hintFields, " | ")

	resize := func() {
		x, y := ui.TerminalDimensions()
		grid.SetRect(0, 0, x, y-1)
		hintBar.SetRect(0, y-1, x, y)
	}
	update := func() {
		ui.Render(grid, hintBar)
	}

	resize()
	update()

	hideDrops := false

	filter := func(packets []vpptrace.Packet) []vpptrace.Packet {
		var pkts []vpptrace.Packet
		for _, p := range packets {
			if hideDrops && p.LastCapture().Name == "drop" {
				continue
			}
			pkts = append(pkts, p)
		}
		return pkts
	}

	var tracingNow bool
	var results = make(map[*VppInstance][]vpptrace.Packet, len(instances))

	showResults := func(instance *VppInstance) {
		packets := results[instance]
		if packets == nil {
			return
		}
		pkts := filter(packets)
		s := fmt.Sprintf("%v - [%d packets](fg:yellow,mod:bold) ", label(instance), len(pkts))
		if h := len(packets) - len(pkts); h > 0 {
			s += fmt.Sprintf("(%d hidden) ", h)
		}
		for i, inst := range instances {
			if instance == inst {
				node := nodes[i]
				node.Value = bytes.NewBufferString(s)
				node.Nodes = buildTreeNodes(pkts)
				node.Expanded = false
				break
			}
		}
	}
	trace := func(instance *VppInstance, node *widgets.TreeNode, done chan bool) {
		defer func() {
			done <- true
		}()
		traces, err := tracePackets(instance, TraceTime)
		if err != nil {
			logrus.Errorf("tracing instance %v error: %v", instance, err)
			results[instance] = nil
			s := fmt.Sprintf("%v - [ERROR: %v](fg:yellow)", label(instance), err.Error())
			node.Value = bytes.NewBufferString(s)
			node.Nodes = nil
			node.Expanded = true
		} else if len(traces.Packets) == 0 {
			logrus.Errorf("tracing instance %v: no packets traced", instance)
			results[instance] = nil
			s := fmt.Sprintf("%v - [no packets traced](fg:magenta)", label(instance))
			node.Value = bytes.NewBufferString(s)
			node.Nodes = nil
			node.Expanded = true
		} else {
			logrus.Infof("instance %v traced %v packets", instance, len(traces.Packets))
			results[instance] = traces.Packets
			showResults(instance)
		}
		packetTree.SetNodes(nodes)
		update()
	}
	traceAll := func() {
		if tracingNow {
			return
		}
		tracingNow = true
		logrus.Infof("tracing..")
		oldStyle := packetTree.BorderStyle
		packetTree.BorderStyle = ui.NewStyle(ui.ColorRed, ui.ColorClear)

		done := make(chan bool, len(instances))
		for i, instance := range instances {
			inst := instance
			node := nodes[i]
			s := fmt.Sprintf("%v - [TRACING...](fg:red)", label(instance))
			node.Value = bytes.NewBufferString(s)
			node.Nodes = nil
			go trace(inst, node, done)
		}
		go func() {
			for range instances {
				<-done
			}
			tracingNow = false
			packetTree.BorderStyle = oldStyle
		}()
		packetTree.SetNodes(nodes)
		packetTree.ExpandAll()
		packetTree.ScrollTop()
	}

	previousKey := ""
	uiEvents := ui.PollEvents()
	for {
		e := <-uiEvents
		switch e.ID {
		case "q", "<C-c>":
			return
		case "j", "<Down>":
			packetTree.ScrollDown()
		case "k", "<Up>":
			packetTree.ScrollUp()
		case "<C-d>":
			packetTree.ScrollHalfPageDown()
		case "<C-u>":
			packetTree.ScrollHalfPageUp()
		case "<C-f>", "<PageDown>":
			packetTree.ScrollPageDown()
		case "<C-b>", "<PageUp>":
			packetTree.ScrollPageUp()
		case "g":
			if previousKey == "g" {
				packetTree.ScrollTop()
			}
		case "<Home>":
			packetTree.ScrollTop()
		case "<Enter>":
			packetTree.ToggleExpand()
		case "G", "<End>":
			packetTree.ScrollBottom()
		case "E":
			packetTree.ExpandAll()
		case "C":
			packetTree.CollapseAll()
			packetTree.ScrollTop()
		case "e":
			selected := packetTree.SelectedNode()
			for _, n := range selected.Nodes {
				n.Expanded = true
			}
			packetTree.Expand()
		case "c":
			selected := packetTree.SelectedNode()
			for _, n := range selected.Nodes {
				n.Expanded = false
			}
			packetTree.Expand()
		case "<Resize>":
			resize()
		case "T":
			traceAll()
		case "h":
			hideDrops = !hideDrops
			for _, instance := range instances {
				showResults(instance)
			}
			packetTree.SetNodes(nodes)
			packetTree.CollapseAll()
			packetTree.ScrollTop()
		}
		if previousKey == "g" {
			previousKey = ""
		} else {
			previousKey = e.ID
		}
		update()
	}
}

type packetNode struct {
	node   *widgets.TreeNode
	packet vpptrace.Packet
}

func (c *packetNode) String() string {
	packet := c.packet
	start := packet.Start
	took := packet.Captures[len(packet.Captures)-1].Start
	if start > time.Second*10 {
		start = start.Round(time.Millisecond)
	}
	first := packet.FirstCapture()
	last := packet.LastCapture()
	pktFields := []string{
		fmt.Sprintf("[Packet %4v](fg:blue,mod:bold)", packet.ID),
		fmt.Sprintf("[%2d](fg:blue) nodes", len(packet.Captures)),
		fmt.Sprintf("took [%8v](fg:blue)", took),
		fmt.Sprintf("[%20s](%s) => [%s](%s)", first.Name, colorNode(first.Name), last.Name, colorNode(last.Name)),
	}
	if c.node.Expanded {
		pktFields = append(pktFields, fmt.Sprintf("⏲  [%v](fg:blue)", formatDurTimestamp(start)))
	}
	return strings.Join(pktFields, " | ")
}

type captureNode struct {
	node    *widgets.TreeNode
	capture vpptrace.Capture
}

func (c *captureNode) String() string {
	cptFields := []string{
		fmt.Sprintf("[%s](fg:cyan)", c.capture),
	}
	if c.node.Expanded {
		if c.capture.Start > 0 {
			cptFields = append(cptFields, fmt.Sprintf("⏲  [%v](fg:blue)", c.capture.Start))
		}
	}
	return strings.Join(cptFields, " | ")
}

func formatDurTimestamp(dur time.Duration) string {
	var t time.Time
	t = t.Add(dur)
	return t.Format("15:04:05.00000")
}

func colorNode(n string) string {
	switch n {
	case "drop":
		return "fg:red"
	default:
		return "fg:blue"
	}
}

func writeLogsTo(logs *widgets.Paragraph) io.Writer {
	return &logWriter{logs}
}

type logWriter struct {
	logs *widgets.Paragraph
}

func (l *logWriter) Write(p []byte) (n int, err error) {
	if l.logs.Text != "" && !strings.HasSuffix(l.logs.Text, "\n") {
		l.logs.Text += "\n"
	}
	l.logs.Text += strings.TrimSpace(string(p))
	lines := strings.Split(l.logs.Text, "\n")
	if len(lines) > l.logs.Inner.Dy() {
		l.logs.Text = strings.Join(lines[len(lines)-l.logs.Inner.Dy():], "\n")
	}
	ui.Render(l.logs)
	return len(p), nil
}
