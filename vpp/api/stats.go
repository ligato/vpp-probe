package api

import (
	govppapi "go.fd.io/govpp/api"
)

type (
	// VppStats contains a statistics data from VPP.
	VppStats struct {
		System govppapi.SystemStats
		//govppapi.NodeStats `json:",omitempty"`
		Nodes      []govppapi.NodeCounters `json:",omitempty"`
		Interfaces map[string]InterfaceStats
		Counters   map[string]uint64
	}

	IfaceCounter struct {
		Bytes   uint64
		Packets uint64
		Errors  uint64
		Mcast   uint64
	}

	IfaceStats struct {
		RX *InterfaceCounter `json:"RX,omitempty"`
		TX *InterfaceCounter `json:"TX,omitempty"`
	}

	InterfaceStats struct {
		Rx *InterfaceCounter `json:"RX,omitempty"`
		Tx *InterfaceCounter `json:"TX,omitempty"`

		RxErrors uint64 `json:",omitempty"`
		TxErrors uint64 `json:",omitempty"`

		RxUnicast   *InterfaceCounter `json:",omitempty"`
		RxMulticast *InterfaceCounter `json:",omitempty"`
		RxBroadcast *InterfaceCounter `json:",omitempty"`
		TxUnicast   *InterfaceCounter `json:",omitempty"`
		TxMulticast *InterfaceCounter `json:",omitempty"`
		TxBroadcast *InterfaceCounter `json:",omitempty"`

		Drops   uint64 `json:",omitempty"`
		Punts   uint64 `json:",omitempty"`
		IP4     uint64 `json:",omitempty"`
		IP6     uint64 `json:",omitempty"`
		RxNoBuf uint64 `json:",omitempty"`
		RxMiss  uint64 `json:",omitempty"`
		Mpls    uint64 `json:",omitempty"`
	}

	InterfaceCounter struct {
		Packets uint64
		Bytes   uint64
	}
)

/*func (counter InterfaceCounter) String() string {
	return fmt.Sprintf("%d pkts/%d bytes", counter.Packets, counter.Bytes)
}

func (counter InterfaceCounter) MarshalText() (text []byte, err error) {
	return []byte(counter.String()), nil
}*/
