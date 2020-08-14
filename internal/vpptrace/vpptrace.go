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

package vpptrace

import (
	"fmt"
	"io/ioutil"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// List of trace-able input nodes.
const (
	AF_PACKET_INPUT    = "af-packet-input"
	AVF_INPUT          = "avf-input"
	BOND_PROCESS       = "bond-process"
	DPDK_CRYPTO_INPUT  = "dpdk-crypto-input"
	DPDK_INPUT         = "dpdk-input"
	HANDOFF_TRACE      = "handoff-trace"
	IXGE_INPUT         = "ixge-input"
	MEMIF_INPUT        = "memif-input"
	MRVL_PP2_INPUT     = "mrvl-pp2-input"
	NETMAP_INPUT       = "netmap-input"
	P2P_ETHERNET_INPUT = "p2p-ethernet-input"
	PG_INPUT           = "pg-input"
	PUNT_SOCKET_RX     = "punt-socket-rx"
	RDMA_INPUT         = "rdma-input"
	SESSION_QUEUE      = "session-queue"
	TUNTAP_RX          = "tuntap-rx"
	VHOST_USER_INPUT   = "vhost-user-input"
	VIRTIO_INPUT       = "virtio-input"
	VMXNET3_INPUT      = "vmxnet3-input"
)

var ALL = []string{
	AF_PACKET_INPUT,
	AVF_INPUT,
	BOND_PROCESS,
	//DPDK_CRYPTO_INPUT,
	//DPDK_INPUT,
	//HANDOFF_TRACE,
	//IXGE_INPUT,
	MEMIF_INPUT,
	//MRVL_PP2_INPUT,
	//NETMAP_INPUT,
	P2P_ETHERNET_INPUT,
	PG_INPUT,
	PUNT_SOCKET_RX,
	RDMA_INPUT,
	SESSION_QUEUE,
	TUNTAP_RX,
	VHOST_USER_INPUT,
	VIRTIO_INPUT,
	VMXNET3_INPUT,
}

// Traces contains list of traced packets.
type Traces struct {
	Packets []Packet
	// TODO: store thread info??
}

// Packet is a single packet from trace.
type Packet struct {
	ID       int
	Captures []Capture
	Start    time.Duration
}

func (p Packet) String() string {
	return fmt.Sprintf("Packet %v", p.ID)
}

func (p *Packet) FirstCapture() *Capture {
	if len(p.Captures) > 0 {
		return &p.Captures[0]
	}
	return nil
}

func (p *Packet) LastCapture() *Capture {
	if len(p.Captures) > 0 {
		return &p.Captures[len(p.Captures)-1]
	}
	return nil
}

// Capture is single capture from packet.
type Capture struct {
	Name    string        // Node name
	Start   time.Duration // Elapsed time since boot
	Content string
}

func (c Capture) String() string {
	return fmt.Sprintf("%s", c.Name)
}

// CLI is interface providing access to VPP CLI.
type CLI interface {
	RunCli(cmd string) (string, error)
}

// Tracer handles tracing.
type Tracer struct {
	cli CLI
}

// NewTracer returns Tracer that uses CLI to manage tracing.
func NewTracer(cli CLI) (*Tracer, error) {
	tracer := &Tracer{
		cli: cli,
	}
	return tracer, nil
}

const maxPackets = 1000

func (t *Tracer) BeginTrace(nodes ...string) error {
	if len(nodes) == 0 {
		return fmt.Errorf("no nodes to trace")
	}
	if err := t.clearTrace(); err != nil {
		return err
	}
	for _, node := range nodes {
		if err := t.addTrace(node, maxPackets); err != nil {
			return err
		}
	}
	return nil
}

func (t *Tracer) EndTrace() (*Traces, error) {
	traceData, err := t.showTrace()
	if err != nil {
		return nil, err
	}
	traceData = strings.ReplaceAll(traceData, "\r\n", "\n")
	trace, err := ParseTrace(traceData)
	if err != nil {
		return nil, fmt.Errorf("parsing trace failed: %v", err)
	}
	f, _ := ioutil.TempFile("", fmt.Sprintf("vpptrace_%d_-*", len(trace.Packets)))
	defer f.Close()
	if _, err := f.WriteString(traceData); err != nil {
		panic(err)
	}
	return trace, nil
}

func (t *Tracer) showTrace() (string, error) {
	reply, err := t.cli.RunCli("show trace max 10000")
	if err != nil {
		return "", err
	}
	return reply, nil
}

func (t *Tracer) addTrace(node string, count int) error {
	_, err := t.cli.RunCli(fmt.Sprintf("trace add %s %d", node, count))
	if err != nil {
		return err
	}
	return nil
}

func (t *Tracer) clearTrace() error {
	_, err := t.cli.RunCli("clear trace")
	if err != nil {
		return err
	}
	return nil
}

var reShowTrace = regexp.MustCompile("(?m)(?:[-]+ Start of thread ([0-9]+) ([[:word:]]+) [-]+\n((?s).*))+")
var reTracePacket = regexp.MustCompile("(?:((?:[0-9]{2}:)+[0-9]{6}): (\\S+)\n)")

func ParseTrace(ss string) (*Traces, error) {
	s := strings.ReplaceAll(ss, "\r", "")

	logrus.Debugf("-> parsing trace %d bytes (%d stripped)", len(s), len(ss)-len(s))
	//logrus.Tracef("%q", s)

	matches := reShowTrace.FindAllStringSubmatch(s, -1)
	logrus.Debugf("-> %d matches", len(matches))

	trace := &Traces{}
	for _, match := range matches {
		packets := strings.Split(strings.TrimSpace(match[3]), "\n\n")
		logrus.Debugf("-> %d packets", len(packets))
		var packet Packet
		for _, pkt := range packets {
			if strings.HasPrefix(pkt, "Packet") {
				idstr := strings.TrimPrefix(pkt, "Packet ")
				id, err := strconv.Atoi(idstr)
				if err != nil {
					fmt.Printf("invalid packet ID %v: %v", idstr, err)
					panic(err)
					continue
				}
				packet = Packet{
					ID: id,
				}
				continue
			}
			captures := reTracePacket.FindAllStringSubmatch(pkt, -1)
			capturesIndex := reTracePacket.FindAllStringSubmatchIndex(pkt, -1)
			for c, capture := range captures {
				if len(capture) < 3 {
					fmt.Println("invalid capture")
					panic("invalid capture")
					continue
				}
				start, err := parseTimestamp(capture[1])
				if err != nil {
					fmt.Println(err)
					panic("invalid timestamp")
					continue
				}
				if c == 0 {
					packet.Start = start
				}
				var capt string
				if len(capturesIndex) <= c+1 {
					capt = pkt[capturesIndex[c][1]:]
				} else {
					capt = pkt[capturesIndex[c][1]:capturesIndex[c+1][0]]
				}
				var content string
				captLines := strings.Split(capt, "\n")
				if len(captLines) > 0 {
					l := strings.TrimLeft(captLines[0], " ")
					prefix := strings.TrimSuffix(captLines[0], l)
					for _, line := range captLines {
						if len(line) == 0 {
							continue
						}
						line = strings.TrimRight(line, " \n\r")
						content += fmt.Sprintf("%s\n", strings.TrimPrefix(line, prefix))
					}
				}
				cpt := Capture{
					Start:   start - packet.Start,
					Name:    capture[2],
					Content: content,
				}
				packet.Captures = append(packet.Captures, cpt)
			}
			if len(packet.Captures) > 0 {
				trace.Packets = append(trace.Packets, packet)
			}
		}
	}
	return trace, nil
}

func parseTimestamp(s string) (time.Duration, error) {
	elap := strings.Split(s, ":")
	if len(elap) != 4 || len(elap[3]) != 6 {
		return 0, fmt.Errorf("invalid trace time format: %q", s)
	}
	hour, _ := strconv.Atoi(elap[0])
	min, _ := strconv.Atoi(elap[1])
	sec, _ := strconv.Atoi(elap[2])
	dur := fmt.Sprintf("%sus", elap[3])
	if sec > 0 {
		dur = fmt.Sprintf("%ds%s", sec, dur)
	}
	if min > 0 {
		dur = fmt.Sprintf("%dm%s", min, dur)
	}
	if hour > 0 {
		dur = fmt.Sprintf("%dh%s", hour, dur)
	}
	start, err := time.ParseDuration(dur)
	if err != nil {
		return 0, fmt.Errorf("parsing duration %q failed: %v", dur, err)
	}
	return start, nil
}
