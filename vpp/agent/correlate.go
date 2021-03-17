package agent

import (
	"fmt"
)

// IPSecCorrelations define corrrelation maps for IPSec.
type IPSecCorrelations struct {
	SrcInstanceMap  map[string]*Instance
	InSpSrcDestMap  map[string]map[string]VppIPSecSP
	OutSpSrcDestMap map[string]map[string]VppIPSecSP
}

// CorrelateIPSec processes list of instances and returns IPSec correlations.
func CorrelateIPSec(instances []*Instance) (*IPSecCorrelations, error) {
	data := &IPSecCorrelations{
		SrcInstanceMap:  map[string]*Instance{},
		InSpSrcDestMap:  map[string]map[string]VppIPSecSP{},
		OutSpSrcDestMap: map[string]map[string]VppIPSecSP{},
	}

	// create a lookup of SP by src & dest
	for _, instance := range instances {
		if !HasAnyIPSecConfig(instance.Config) {
			continue
		}
		ipsecSPs := instance.Config.VPP.IPSecSPs
		for _, sp := range ipsecSPs {
			srcIp := sp.Value.LocalAddrStart
			dstIp := sp.Value.RemoteAddrStart

			data.SrcInstanceMap[srcIp] = instance

			if sp.Value.IsOutbound {
				if _, ok := data.OutSpSrcDestMap[srcIp]; !ok {
					data.OutSpSrcDestMap[srcIp] = make(map[string]VppIPSecSP)
				}
				data.OutSpSrcDestMap[srcIp][dstIp] = sp
			} else {
				if _, ok := data.InSpSrcDestMap[srcIp]; !ok {
					data.InSpSrcDestMap[srcIp] = make(map[string]VppIPSecSP)
				}
				data.InSpSrcDestMap[srcIp][dstIp] = sp
			}
		}
	}

	if len(data.InSpSrcDestMap) == 0 {
		return nil, fmt.Errorf("no IPSec correlations found")
	}

	return data, nil
}
