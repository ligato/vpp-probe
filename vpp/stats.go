package vpp

import (
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
	govppapi "go.fd.io/govpp/api"

	"go.ligato.io/vpp-probe/vpp/api"
)

func ListStats(stats govppapi.StatsProvider) ([]string, error) {
	var sys govppapi.SystemStats
	if err := stats.GetSystemStats(&sys); err != nil {
		return nil, err
	}
	var ifstats govppapi.InterfaceStats
	if err := stats.GetInterfaceStats(&ifstats); err != nil {
		return nil, err
	}
	var counters govppapi.ErrorStats
	if err := stats.GetErrorStats(&counters); err != nil {
		return nil, err
	}

	var str string
	sysStr, err := yamlTmpl(sys)
	if err != nil {
		logrus.Warnf("marshaling system stats failed: %v", err)
		sysStr = err.Error()
	}
	ifaceStr, err := yamlTmpl(ifstats)
	if err != nil {
		logrus.Warnf("marshaling interface stats failed: %v", err)
		ifaceStr = err.Error()
	}
	countersStr, err := yamlTmpl(counters)
	if err != nil {
		logrus.Warnf("marshaling error stats failed: %v", err)
		countersStr = err.Error()
	}

	str += fmt.Sprintf("System stats:\n---------------\n%v\n\n", sysStr)
	str += fmt.Sprintf("Interface stats:\n---------------\n%s\n\n", ifaceStr)
	str += fmt.Sprintf("Counters:\n---------------\n%s\n\n", countersStr)
	s := strings.Split(str, "\n")

	return s, nil
}

func DumpStats(stats govppapi.StatsProvider) (*api.VppStats, error) {
	var sys govppapi.SystemStats
	if err := stats.GetSystemStats(&sys); err != nil {
		return nil, err
	}

	var nodestats govppapi.NodeStats
	if err := stats.GetNodeStats(&nodestats); err != nil {
		return nil, err
	}

	var ifacestats govppapi.InterfaceStats
	if err := stats.GetInterfaceStats(&ifacestats); err != nil {
		return nil, err
	}
	interfaces := map[string]api.InterfaceStats{}
	for _, c := range ifacestats.Interfaces {
		ifaceCounters := api.InterfaceStats{
			Rx:          toCombined(c.Rx),
			Tx:          toCombined(c.Tx),
			RxErrors:    c.RxErrors,
			TxErrors:    c.TxErrors,
			RxUnicast:   toCombined(c.RxUnicast),
			RxMulticast: toCombined(c.RxMulticast),
			RxBroadcast: toCombined(c.RxBroadcast),
			TxUnicast:   toCombined(c.TxUnicast),
			TxMulticast: toCombined(c.TxMulticast),
			TxBroadcast: toCombined(c.TxBroadcast),
			Drops:       c.Drops,
			Punts:       c.Punts,
			IP4:         c.IP4,
			IP6:         c.IP6,
			RxNoBuf:     c.RxNoBuf,
			RxMiss:      c.RxMiss,
			Mpls:        c.Mpls,
		}
		interfaces[c.InterfaceName] = ifaceCounters
	}

	var errstats govppapi.ErrorStats
	if err := stats.GetErrorStats(&errstats); err != nil {
		return nil, err
	}
	counters := map[string]uint64{}
	for _, c := range errstats.Errors {
		var value uint64
		for _, val := range c.Values {
			value += val
		}
		if value > 0 {
			counters[c.CounterName] = value
		}
	}

	s := &api.VppStats{
		System: sys,
		Nodes:  nodestats.Nodes,
		//NodeStats:  nodestats,
		Interfaces: interfaces,
		Counters:   counters,
	}

	return s, nil
}

func toCombined(cc govppapi.InterfaceCounterCombined) *api.InterfaceCounter {
	if cc.Bytes == 0 && cc.Packets == 0 {
		return nil
	}
	return &api.InterfaceCounter{
		Packets: cc.Packets,
		Bytes:   cc.Bytes,
	}
}
