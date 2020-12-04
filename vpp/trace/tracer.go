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

package trace

import (
	"fmt"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// CLI is interface providing access to VPP CLI.
type CLI interface {
	RunCli(cmd string) (string, error)
}

// Result contains trace results.
type Result struct {
	// TraceTime is the actual time when the result was done
	TraceTime time.Time
	// Packets is a list of traced packets
	Packets []Packet
	// RawData is the raw trace data before parsing
	RawData string
}

// Packet is a single packet from trace.
type Packet struct {
	// ID is a packet number
	ID int
	// Captures contains captured data for packet
	Captures []Capture
}

// Start returns an uptime (elapsed time since boot) when packet started.
func (p *Packet) Start() time.Duration {
	if first := p.FirstCapture(); first != nil {
		return first.Start
	}
	return 0
}

func (p *Packet) FirstCapture() *Capture {
	if len(p.Captures) == 0 {
		return nil
	}
	return &p.Captures[0]
}

func (p *Packet) LastCapture() *Capture {
	if len(p.Captures) == 0 {
		return nil
	}
	return &p.Captures[len(p.Captures)-1]
}

// Capture is a single capture from traced packet.
type Capture struct {
	// Name is name of capture node
	Name string
	// Start is elapsed time since packet started
	Start time.Duration
	// Content is raw capture data
	Content string
}

const (
	defaultNumPackets = 5000
)

// Tracer manages packet tracing.
type Tracer struct {
	cli CLI

	numPackets int
	toRetrieve int
}

// NewTracer returns Tracer that uses CLI to manage tracing.
func NewTracer(cli CLI) (*Tracer, error) {
	tracer := &Tracer{
		cli:        cli,
		numPackets: defaultNumPackets,
	}
	return tracer, nil
}

// SetNumPackets sets the number of packets to trace. By default, 5000 packets are traced.
func (t *Tracer) SetNumPackets(numPackets int) {
	if numPackets <= 0 {
		return
	}
	t.numPackets = numPackets
}

// BeginTrace starts tracing packets for nodes.
func (t *Tracer) BeginTrace(nodes ...string) error {
	if len(nodes) == 0 {
		return fmt.Errorf("no nodes to trace")
	}
	cmds := []string{
		"clear trace",
	}
	t.toRetrieve = 0
	for _, node := range nodes {
		cmd := fmt.Sprintf("trace add %s %d", node, t.numPackets)
		cmds = append(cmds, cmd)
		t.toRetrieve += t.numPackets
	}
	out, err := t.cli.RunCli(strings.Join(cmds, "\n"))
	if err != nil {
		return fmt.Errorf("trace command failed: %w\n%s", err, out)
	}
	return nil
}

// EndTrace stops tracing, parses and returns trace Result.
func (t *Tracer) EndTrace() (*Result, error) {
	traceData, err := t.showTrace()
	if err != nil {
		return nil, err
	}
	traceTime := time.Now()

	packets, err := ParseTracePackets(traceData)
	if err != nil {
		return nil, fmt.Errorf("parsing trace failed: %v", err)
	}
	if len(packets) == 0 {
		logrus.Debugf("no packets parsed from trace data:\n%s", traceData)
	}
	result := &Result{
		TraceTime: traceTime,
		RawData:   traceData,
		Packets:   packets,
	}
	return result, nil
}

func (t *Tracer) addTrace(node string, count int) error {
	_, err := t.cli.RunCli(fmt.Sprintf("trace add %s %d", node, count))
	if err != nil {
		return err
	}
	return nil
}

func (t *Tracer) showTrace() (string, error) {
	count := t.toRetrieve
	if count < t.numPackets {
		count = t.numPackets
	}
	cmd := fmt.Sprintf("show trace max %d", count)
	reply, err := t.cli.RunCli(cmd)
	if err != nil {
		return "", err
	}
	return reply, nil
}

func (t *Tracer) clearTrace() error {
	_, err := t.cli.RunCli("clear trace")
	if err != nil {
		return err
	}
	return nil
}
