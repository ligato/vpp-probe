package vpptrace

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

var (
	reShowTrace   = regexp.MustCompile("(?m)(?:[-]+ Start of thread ([0-9]+) ([[:word:]]+) [-]+\n((?s).*))+")
	reTracePacket = regexp.MustCompile("(?:((?:[0-9]{2}:)+[0-9]{6}): (\\S+)\n)")
	// TODO: parse thread info? would that be useful?
)

const (
	tracePacketPrefix = "Packet "
	noPacketsInBuffer = "No packets in trace buffer"
)

// ParseResult parses raw trace output and returns Result with parsed Packet(s)
// or error in case the trace output cannot be parsed.
func ParseTracePackets(trace string) (packets []Packet, err error) {
	trace = normalizeLines(trace)

	matches := reShowTrace.FindAllStringSubmatch(trace, -1)
	logrus.Debugf("-> %d matches", len(matches))

	if len(matches) == 0 && !strings.Contains(trace, noPacketsInBuffer) {
		return nil, fmt.Errorf("unable to parse trace data")
	}

	for _, match := range matches {
		pkts := strings.Split(strings.TrimSpace(match[3]), "\n\n")
		logrus.Debugf("-> %d packets", len(pkts))

		var packet Packet

		for _, pkt := range pkts {
			if idstr := strings.TrimPrefix(pkt, tracePacketPrefix); idstr != pkt {
				id, err := strconv.Atoi(idstr)
				if err != nil {
					logrus.Warnf("invalid packet ID %v: %v", idstr, err)
					continue
				}
				packet = Packet{
					ID: id,
				}
				continue
			}

			packet.Captures, err = ParseTraceCaptures(pkt)
			if err != nil {
				logrus.Warn(err)
				continue
			}
			if len(packet.Captures) == 0 {
				continue
			}
			packet.Start = packet.FirstCapture().Start
			packets = append(packets, packet)

		}
	}

	return packets, nil
}

func ParseTraceCaptures(pkt string) ([]Capture, error) {
	var captures []Capture

	captureMatches := reTracePacket.FindAllStringSubmatch(pkt, -1)
	indexMatches := reTracePacket.FindAllStringSubmatchIndex(pkt, -1)

	for c, capture := range captureMatches {
		if len(capture) < 3 {
			logrus.Warnf("invalid capture data (idx %d)", c)
			continue
		}
		start, err := parseTimestamp(capture[1])
		if err != nil {
			logrus.Warnf("invalid capture timestamp: %v", err)
			continue
		}
		/* if c == 0 {
		    packet.Start = start
		}*/
		var capt string
		if len(indexMatches) <= c+1 {
			capt = pkt[indexMatches[c][1]:]
		} else {
			capt = pkt[indexMatches[c][1]:indexMatches[c+1][0]]
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
			Start:   start, // - packet.Start,
			Name:    capture[2],
			Content: content,
		}
		captures = append(captures, cpt)
	}
	return captures, nil
}

func normalizeLines(data string) string {
	ss := strings.ReplaceAll(data, "\r\n", "\n")
	return strings.ReplaceAll(ss, "\r", "")
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
