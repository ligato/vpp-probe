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

// Result contains trace results.
type Result struct {
	TraceTime time.Time // TraceTime is the actual time of trace
	Packets   []Packet  // Packets is a list of traced packets
	RawData   string    // RawData is the raw trace data before parsing
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

// BeginTrace clears the trace and starts tracing packets of nodes.
func (t *Tracer) BeginTrace(nodes ...string) error {
	if len(nodes) == 0 {
		return fmt.Errorf("no nodes to trace")
	}

	numPackets := t.numPackets

	cmds := []string{
		"clear trace",
	}
	for _, node := range nodes {
		cmds = append(cmds, fmt.Sprintf("trace add %s %d", node, numPackets))
	}
	out, err := t.cli.RunCli(strings.Join(cmds, "\n"))
	if err != nil {
		return fmt.Errorf("trace command failed: %w\n%s", err, out)
	}

	t.toRetrieve = numPackets * len(nodes)

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

	reply, err := t.cli.RunCli(fmt.Sprintf("show trace max %d", count))
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
