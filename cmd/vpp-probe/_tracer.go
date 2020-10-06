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
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	ui "github.com/gizak/termui/v3"
	"github.com/gizak/termui/v3/widgets"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"go.ligato.io/vpp-probe/pkg/probeui"

	probe "go.ligato.io/vpp-probe"
	"go.ligato.io/vpp-probe/controller"
	"go.ligato.io/vpp-probe/pkg/vpptrace"
	"go.ligato.io/vpp-probe/vpp"
)

var DefaultTracerOptions = TracerOptions{
	TraceDir:   os.TempDir(),
	TraceTime:  time.Second * 5,
	TraceNodes: vpptrace.CommonNodes,
	NumPackets: 10000,
}

func NewTracerCmd(vppctx *controller.Controller) *cobra.Command {
	var (
		opts = DefaultTracerOptions
	)
	cmd := &cobra.Command{
		Use:     "tracer",
		Short:   "Analyze traced packets from VPP instance(s)",
		Long:    "Trace packets inside processing nodes of running VPP(s) and browse the captured results",
		Aliases: []string{"trace", "tr", "tracing"},
		Args:    cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTracer(vppctx, opts)
		},
	}
	flags := cmd.Flags()
	flags.StringVar(&opts.TraceDir, "tracedir", opts.TraceDir, "Directory to store raw trace data")
	flags.StringSliceVar(&opts.TraceNodes, "tracenodes", opts.TraceNodes, "List of traced nodes")
	flags.DurationVarP(&opts.TraceTime, "tracedur", "d", opts.TraceTime, "Duration of tracing")
	flags.UintVar(&opts.NumPackets, "numpackets", opts.NumPackets, "Number of packets to trace per node")
	return cmd
}

type TracerOptions struct {
	TraceDir   string
	TraceTime  time.Duration
	TraceNodes []string
	NumPackets uint
}

func runTracer(vppctx *controller.Controller, opts TracerOptions) error {
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

	instances := vppctx.Instances()

	logrus.Debugf("init tracer with %d instances..", len(instances))

	return traceViewer(instances, opts)
}

func traceViewer(instances []*vpp.Instance, opts TracerOptions) error {
	if err := probeui.InitUI(); err != nil {
		return fmt.Errorf("failed to initialize termui: %v", err)
	}
	defer ui.Close()

	/*toolbar := widgets.NewParagraph()
	toolbar.Title = "[ VPP Instances ]"
	toolbar.TitleStyle = ui.NewStyle(ColorLightWhite, ColorLightBlack)
	for i, instance := range instances {
		index := i + 1
		ver := instance.Version
		if parts := strings.Fields(instance.Version); len(parts) > 3 {
			ver = parts[1]
		}
		toolbar.Text += fmt.Sprintf(" %d. [%v](fg:yellow) | %s\n", index, instance, ver)
	}*/

	packetTree := widgets.NewTree()
	packetTree.Title = "[ Packet Tracer ]"
	packetTree.TitleStyle = ui.NewStyle(probeui.ColorLightWhite, probeui.ColorLightBlack)
	packetTree.SelectedRowStyle = ui.NewStyle(ui.ColorClear, ui.ColorClear, ui.ModifierReverse)
	packetTree.WrapText = true
	packetTree.PaddingLeft = 1
	packetTree.BorderStyle = ui.NewStyle(ui.ColorClear, ui.ColorClear)

	label := func(instance *probe.VPPInstance) string {
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
	logrus.SetOutput(probeui.WriteLogsTo(logs))

	grid := ui.NewGrid()
	grid.Set(
		/*ui.NewRow(.1,
			ui.NewCol(1.0, toolbar),
		),*/
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

	var searchOn bool
	var oldTitle string
	var oldStyle ui.Style
	var searchQuery string
	updateSearch := func() {
		hintBar.Title = fmt.Sprintf("SEARCH: %q", searchQuery)
	}
	beginSearch := func() {
		oldTitle = hintBar.Title
		oldStyle = hintBar.TitleStyle
		hintBar.Title = fmt.Sprintf("SEARCH: _")
		hintBar.TitleStyle = ui.NewStyle(probeui.ColorLightYellow, ui.ColorBlack)
		searchOn = true
	}
	endSearch := func() {
		hintBar.Title = oldTitle
		hintBar.TitleStyle = oldStyle
		searchOn = false
	}

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
	var results = make(map[*probe.VPPInstance][]vpptrace.Packet, len(instances))

	showResults := func(instance *probe.VPPInstance) {
		packets := results[instance]
		if packets == nil {
			return
		}
		pkts := filter(packets)
		s := fmt.Sprintf("%v - [%d packets traced](fg:yellow,mod:bold) ", label(instance), len(pkts))
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
	trace := func(instance *probe.VPPInstance, node *widgets.TreeNode, done chan bool) {
		defer func() {
			done <- true
		}()
		traces, err := tracePackets(instance, opts.TraceNodes, opts.TraceTime)
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
			s := fmt.Sprintf("%v - [no packets traced](fg:white,bg:black)", label(instance))
			node.Value = bytes.NewBufferString(s)
			node.Nodes = nil
			node.Expanded = true
		} else {
			logrus.Infof("instance %v traced %v packets", instance, len(traces.Packets))
			results[instance] = traces.Packets
			if opts.TraceDir != "" {
				saveTraceData(opts.TraceDir, instance, traces)
			}
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
		logrus.Infof("begin tracing..")
		oldStyle := packetTree.BorderStyle
		packetTree.BorderStyle = ui.NewStyle(ui.ColorRed, ui.ColorClear)

		done := make(chan bool, len(instances))
		for i, instance := range instances {
			inst := instance
			node := nodes[i]
			s := fmt.Sprintf("%v \t[⌛ TRACING...](fg:red,mod:blink)", label(instance))
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
		case "<C-c>":
			return nil
		case "<Resize>":
			resize()
			update()
			continue
		}

		if searchOn {
			switch e.ID {
			case "<Escape>":
				endSearch()
			case "<Backspace>":
				if searchQuery != "" {
					searchQuery = searchQuery[:len(searchQuery)-1]
				}
			default:
				x := strings.ToLower(e.ID)
				if unicode.IsLetter(rune(e.ID[0])) {
					searchQuery += x
				}
			}
			updateSearch()
			update()
			continue
		}

		switch e.ID {
		case "q", "<C-c>":
			return nil
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
		case "T":
			traceAll()
		case "s":
			beginSearch()
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

func tracePackets(instance *probe.VPPInstance, traceNodes []string, dur time.Duration) (*vpptrace.Result, error) {
	tracer, err := vpptrace.NewTracer(instance)
	if err != nil {
		return nil, err
	}
	// TODO: select specific nodes
	err = tracer.BeginTrace(traceNodes...)
	if err != nil {
		return nil, err
	}

	logrus.Debugf("tracing packets for %v..", dur)
	time.Sleep(dur)

	trace, err := tracer.EndTrace()
	if err != nil {
		return nil, err
	}

	return trace, nil
}

func saveTraceData(traceDir string, instance *probe.VPPInstance, trace *vpptrace.Result) {
	t := time.Now()
	host, _ := os.Hostname()

	s := strings.ReplaceAll(instance.String(), " ", "-")
	name := fmt.Sprintf("vpptrace_%s_%s_%dpkts.txt", strings.ToLower(s), t.Format("2015-Feb-25_11:06:39"), len(trace.Packets))

	dir := filepath.Join(traceDir, name)
	file, err := os.OpenFile(dir, os.O_WRONLY|os.O_CREATE, 0655)
	if err != nil {
		logrus.Warnf("failed to save trace data to dir %s: %v", dir, err)
		return
	}
	defer file.Close()

	fmt.Fprintln(file, "# ========================================")
	fmt.Fprintln(file, "#  VPP PACKET TRACE")
	fmt.Fprintln(file, "# ========================================")
	fmt.Fprintln(file, "#      Time:", t.Format(time.UnixDate))
	fmt.Fprintln(file, "#      Host:", host)
	fmt.Fprintln(file, "# ----------------------------------------")
	fmt.Fprintln(file, "#   Version:", instance.Version)
	fmt.Fprintln(file, "# ----------------------------------------")
	fmt.Fprintln(file)
	fmt.Fprint(file, trace.RawData)
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

type packetNode struct {
	node   *widgets.TreeNode
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
	pktFields := []string{
		fmt.Sprintf("[Packet](mod:bold) [%4v](fg:blue)", fmt.Sprintf("%03d", packet.ID)),
		fmt.Sprintf("nodes [%2d](fg:blue)", len(packet.Captures)),
		fmt.Sprintf("took [%9v](fg:blue)", took),
		fmt.Sprintf("[%20s](%s)  ￫  [%s](%s)", first.Name, getNodeColor(first.Name), last.Name, getNodeColor(last.Name)),
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
		fmt.Sprintf("[%s](fg:cyan)", c.capture.Name),
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

func getNodeColor(n string) string {
	switch n {
	case "drop":
		return "fg:red"
	default:
		return "fg:magenta"
	}
}
