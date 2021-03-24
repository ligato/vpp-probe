package agent

import (
	"fmt"
)

// IPSecCorrelations define corrrelation maps for IPSec.
type IPSecCorrelations struct {
	SrcInstanceMap  map[string]*Instance
	InSpSrcDestMap  map[string]map[string]VppIPSecSP
	OutSpSrcDestMap map[string]map[string]VppIPSecSP
	SpiInSrcDestMap map[uint32][]VppIPSecSP   // SPI key
	SpiOutSrcDestMap map[uint32][]VppIPSecSP  // SPI key
}

// CorrelateIPSec processes list of instances and returns IPSec correlations.
func CorrelateIPSec(instances []*Instance) (*IPSecCorrelations, error) {
	data := &IPSecCorrelations{
		SrcInstanceMap:  map[string]*Instance{},
		InSpSrcDestMap:  map[string]map[string]VppIPSecSP{},
		OutSpSrcDestMap: map[string]map[string]VppIPSecSP{},
		SpiInSrcDestMap: map[uint32][]VppIPSecSP{},
		SpiOutSrcDestMap: map[uint32][]VppIPSecSP{},
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
				outSa := FindIPSecSA(sp.Value.SaIndex, instance.Config.VPP.IPSecSAs)
				data.SpiOutSrcDestMap[outSa.Value.Spi] = append(data.SpiOutSrcDestMap[outSa.Value.Spi], sp)
				if _, ok := data.OutSpSrcDestMap[srcIp]; !ok {
					data.OutSpSrcDestMap[srcIp] = make(map[string]VppIPSecSP)
				}
				data.OutSpSrcDestMap[srcIp][dstIp] = sp
			} else {
				inSa := FindIPSecSA(sp.Value.SaIndex, instance.Config.VPP.IPSecSAs)
				data.SpiInSrcDestMap[inSa.Value.Spi] = append(data.SpiInSrcDestMap[inSa.Value.Spi], sp)
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
