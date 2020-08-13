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
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"git.fd.io/govpp.git"
	"git.fd.io/govpp.git/adapter"
	ui "github.com/gizak/termui/v3"
	"github.com/gizak/termui/v3/widgets"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"go.ligato.io/vpp-agent/v3/plugins/vpp/binapi/vpp2005/interfaces"

	"go.ligato.io/vpp-probe/pkg/vppcli"
)

func init() {
	rootCmd.AddCommand(probeCmd)

	probeCmd.Flags().StringVar(&kubeconfigs, "kubeconfigs", "", "Directory with kubeconfigs")
	probeCmd.Flags().StringSliceVarP(&queriesFlag, "query", "q", []string{}, "Queries for pods")
}

var probeCmd = &cobra.Command{
	Use:   "probe",
	Short: "Probe running VPP instances",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runProbe()
	},
}

func runProbe() error {
	/*if kubeconfigs != "" {
		configs, err := loadConfigs(kubeconfigs)
		if err != nil {
			return fmt.Errorf("loading kubeconfigs failed: %w", err)
		}
		if len(configs) == 0 {
			return fmt.Errorf("no kubeconfigs found in %s", kubeconfigs)
		}

		queries := parseQueries(queriesFlag)
		if len(queries) == 0 {
			return fmt.Errorf("at least one query neeeded")
		}

		for _, config := range configs {
			apicfg, err := clientcmd.LoadFromFile(config)
			if err != nil {
				return fmt.Errorf("config %s error: %v", config, err)
			}
			instances, err := findInCluster(config, queries)
			if err != nil {
				return fmt.Errorf("cluster %s error: %v", apicfg.CurrentContext, err)
			}

			printInstances(apicfg, instances)
		}
	}*/

	conn, err := govpp.Connect(adapter.DefaultBinapiSocket)
	if err != nil {
		return fmt.Errorf("connecting to VPP failed: %v", err)
	}
	defer conn.Disconnect()
	ch, err := conn.NewAPIChannel()
	if err != nil {
		logrus.Fatalln("ERROR: creating channel:", err)
	}
	defer conn.Disconnect()

	events := make(chan *interfaces.SwInterfaceEvent, 100)
	err = WatchInterfaceEvents(context.Background(), conn, events)
	if err != nil {
		return fmt.Errorf("WatchInterfaceEvents failed: %v", err)
	}

	probe(vppcli.Default, func() []*Interface {
		return dumpInterfaces(ch)
	}, events)
	return nil
}

func probe(cli vppcli.CLI, dump func() []*Interface, ifevents chan *interfaces.SwInterfaceEvent) {
	if err := ui.Init(); err != nil {
		log.Fatalf("failed to initialize termui: %v", err)
	}
	defer ui.Close()

	table := widgets.NewTable()
	tableHeader := []string{"Interface", "Idx", "Type", "State", "IP", "VRF", "MTU (l3/ip4/ip6/mpls/link)"}
	table.Rows = [][]string{tableHeader}
	table.TextStyle = ui.NewStyle(ui.ColorWhite)
	table.TextAlignment = ui.AlignCenter
	table.RowSeparator = false
	table.FillRow = true
	table.PaddingLeft = 1
	table.PaddingRight = 1
	//table.RowStyles[0] = ui.NewStyle(ui.ColorBlack, ui.ColorWhite)
	table.RowStyles[0] = ui.NewStyle(ui.ColorWhite, ui.ColorClear, ui.ModifierBold)
	table.ColumnResizer = func() {
		var columnWidths []int
		columnCount := len(table.Rows[0])
		columnWidth := table.Inner.Dx() / columnCount
		for i := 0; i < columnCount; i++ {
			columnWidths = append(columnWidths, columnWidth)
		}
		setColW := func(c int, w int) {
			if columnWidths[c] > w {
				x := columnWidths[c] - w
				columnWidths[c] = w
				columnWidths[len(columnWidths)-1] += x
			}
		}
		setColW(1, 3)
		setColW(5, 3)
		table.ColumnWidths = columnWidths
	}

	logs := widgets.NewParagraph()
	logs.Title = "Events"
	logs.Text = ""
	logs.PaddingLeft = 1

	info := widgets.NewParagraph()
	info.Title = "Info"
	info.PaddingLeft = 1

	grid := ui.NewGrid()
	termWidth, termHeight := ui.TerminalDimensions()
	grid.SetRect(0, 0, termWidth, termHeight)
	grid.Set(
		ui.NewRow(.2,
			ui.NewCol(1.0, info),
		),
		ui.NewRow(.5,
			ui.NewCol(1.0, table),
		),
		ui.NewRow(.3,
			ui.NewCol(1.0, logs),
		),
	)

	update := func() {
		version, err := cli.RunCli("show version")
		if err != nil {
			log.Fatal(err)
		}
		version = strings.TrimSpace(version)

		uptime, err := cli.RunCli("show clock")
		if err != nil {
			log.Fatal(err)
		}
		uptime = strings.TrimSpace(uptime)
		info.Text = fmt.Sprintf("Version: %v\nUptime: %v", version, uptime)
		//logs.Text += fmt.Sprintf("Version: %v\nUptime: %v", version, uptime)

		list := dump()
		rows := [][]string{
			tableHeader,
		}
		for _, iface := range list {
			name := iface.Name
			if len(strings.TrimSpace(iface.Tag)) > 0 {
				name = fmt.Sprintf("%s (%s)", iface.Name, iface.Tag)
			}
			//typ := fmt.Sprintf("%s (%s)", iface.DevType, iface.Type)
			ips := strings.Join(iface.IPs, ", ")
			rows = append(rows, []string{
				name,
				fmt.Sprint(iface.Index),
				iface.DevType,
				iface.State,
				ips,
				fmt.Sprint(iface.VRF),
				fmt.Sprint(iface.MTU),
			})
		}
		table.Rows = rows
		ui.Render(grid)
	}
	update()

	go func() {
		for {
			select {
			case e := <-ifevents:
				logs.Text += fmt.Sprintf("[iface] index: %v flags:%v del:%v\n", e.SwIfIndex, e.Flags, e.Deleted)
				ui.Render(logs)
			}
		}
	}()

	ticker := time.NewTicker(time.Second).C
	uiEvents := ui.PollEvents()
	for {
		select {
		case e := <-uiEvents:
			switch e.ID {
			case "q", "<C-c>":
				return
			case "<Resize>":
				payload := e.Payload.(ui.Resize)
				grid.SetRect(0, 0, payload.Width, payload.Height)
				ui.Clear()
				ui.Render(grid)
			}
		case <-ticker:
			update()
		}
	}

}
