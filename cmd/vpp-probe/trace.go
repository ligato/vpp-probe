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
	"log"
	"strings"
	"time"

	ui "github.com/gizak/termui/v3"
	"github.com/gizak/termui/v3/widgets"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"go.ligato.io/vpp-probe/pkg/vppcli"
	"go.ligato.io/vpp-probe/pkg/vpptrace"
)

var (
	TraceTarget string
	TraceTime   = time.Second * 3
)

func init() {
	rootCmd.AddCommand(traceCmd)

	traceCmd.Flags().StringVarP(&TraceTarget, "target", "t", "", "Target to trace")
	traceCmd.Flags().DurationVarP(&TraceTime, "duration", "d", TraceTime, "Duration of tracing")
}

var traceCmd = &cobra.Command{
	Use:   "trace",
	Short: "Trace packets",
	RunE: func(cmd *cobra.Command, args []string) error {
		return doTrace()
	},
}

func doTrace() error {
	/*conn, err := govpp.Connect(adapter.DefaultBinapiSocket)
	if err != nil {
		logrus.Fatalln("ERROR: connecting to VPP failed:", err)
	}
	defer conn.Disconnect()

	ch, err := conn.NewAPIChannel()
	if err != nil {
		logrus.Fatalln("ERROR: creating channel:", err)
	}
	defer conn.Disconnect()
	_ = ch*/

	var traceIdx int
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
	}*/

	cli := vppcli.Default

	ver, err := cli.RunCli("show version")
	if err != nil {
		logrus.Fatal(err)
	}
	logrus.Infof("conneted: %v", ver)

	tracer, err := vpptrace.NewTracer(cli)
	if err != nil {
		logrus.Fatal(err)
	}

	err = tracer.BeginTrace(
		/*vpptrace.VIRTIO_INPUT,
		vpptrace.SESSION_QUEUE,
		vpptrace.AF_PACKET_INPUT,
		vpptrace.MEMIF_INPUT,*/
		vpptrace.ALL...,
	)
	if err != nil {
		logrus.Fatal(err)
	}

	logrus.Infof("tracing..")
	time.Sleep(TraceTime)

	trace, err := tracer.EndTrace()
	if err != nil {
		logrus.Fatal(err)
	}
	if len(trace.Packets) == 0 {
		logrus.Fatalf("no packets traced..")
		//continue
	}

	var packets []vpptrace.Packet
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
	} else {
		packets = trace.Packets
	}

	traceView(ver, packets)

	return nil
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

func traceView(version string, packets []vpptrace.Packet) {
	if err := ui.Init(); err != nil {
		log.Fatalf("failed to initialize termui: %v", err)
	}
	defer ui.Close()

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

		start := packet.Start
		took := packet.Captures[len(packet.Captures)-1].Start
		if start > time.Second*10 {
			start = start.Round(time.Millisecond)
		}
		pktFields := []string{
			fmt.Sprintf("[Packet %3v](fg:cyan,mod:bold)", packet.ID),
			fmt.Sprintf("⏲  [%v](fg:blue)", formatDurTimestamp(start)),
			fmt.Sprintf("took [%5v](fg:blue)", took),
			fmt.Sprintf("[%2d](fg:blue) nodes", len(packet.Captures)),
			fmt.Sprintf("%s \uE25B  %s",
				colorNode(packet.FirstCapture().Name), colorNode(packet.LastCapture().Name)),
		}
		packetText := strings.Join(pktFields, " | ")

		pNode := &widgets.TreeNode{
			Value: bytes.NewBufferString(packetText),
			Nodes: captures,
		}
		nodes = append(nodes, pNode)
	}

	packetTree := widgets.NewTree()
	packetTree.Title = fmt.Sprintf(" %d traced packets ", len(packets))
	packetTree.TextStyle = ui.NewStyle(ui.ColorWhite)
	packetTree.SelectedRowStyle = ui.NewStyle(ui.ColorYellow)
	packetTree.WrapText = true
	packetTree.PaddingLeft = 1
	packetTree.SetNodes(nodes)

	toolbar := widgets.NewParagraph()
	toolbar.Title = "VPP Tracer"
	toolbar.Text = fmt.Sprintf("Version: %s", version)

	grid := ui.NewGrid()
	termWidth, termHeight := ui.TerminalDimensions()
	grid.SetRect(0, 0, termWidth, termHeight)
	grid.Set(
		ui.NewRow(.1,
			ui.NewCol(1.0, toolbar),
		),
		ui.NewRow(.9,
			ui.NewCol(1.0, packetTree),
		),
	)

	hintBar := widgets.NewParagraph()
	hintBar.TextStyle = ui.NewStyle(ui.ColorClear, ui.ColorClear, ui.ModifierClear)
	hintBar.Border = false
	hintStyle := "fg:black,bg:white"
	hintFields := []string{
		fmt.Sprintf("[<Up>/<Down>/<Home>/<End>](%[1]s) Move", hintStyle),
		fmt.Sprintf("[<Enter>](%[1]s) Toggle Expand", hintStyle),
		fmt.Sprintf("[<e>/<E>](%[1]s) Expand Nodes/All", hintStyle),
		fmt.Sprintf("[<c>/<C>](%[1]s) Collapse Nodes/All", hintStyle),
		fmt.Sprintf("[<q>](%[1]s) Quit", hintStyle),
	}
	hintBar.Text = strings.Join(hintFields, " | ")

	resize := func() {
		x, y := ui.TerminalDimensions()
		grid.SetRect(0, 0, x, y-1)
		hintBar.SetRect(0, y-1, x, y)
	}
	update := func() {
		packetTree.Walk(func(node *widgets.TreeNode) bool {

			return true
		})
		ui.Render(grid, hintBar)
	}

	resize()
	update()

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
		}
		if previousKey == "g" {
			previousKey = ""
		} else {
			previousKey = e.ID
		}
		update()
	}
}

func formatDurTimestamp(dur time.Duration) string {
	var t time.Time
	t = t.Add(dur)
	return t.Format("15:04:05.00000")
}

func colorNode(n string) string {
	switch n {
	case "drop":
		return fmt.Sprintf("[%s](fg:red)", n)
	default:
		return fmt.Sprintf("[%s](fg:blue)", n)
	}
}
