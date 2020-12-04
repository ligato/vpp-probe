package trace

// List of trace-able input nodes.
const (
	AfPacketInput    = "af-packet-input"
	AvfInput         = "avf-input"
	BondProcess      = "bond-process"
	MemifInput       = "memif-input"
	P2pEthernetInput = "p2p-ethernet-input"
	PgInput          = "pg-input"
	PuntSocketRx     = "punt-socket-rx"
	RdmaInput        = "rdma-input"
	SessionQueue     = "session-queue"
	TuntapRx         = "tuntap-rx"
	VhostUserInput   = "vhost-user-input"
	VirtioInput      = "virtio-input"
	Vmxnet3Input     = "vmxnet3-input"

	// Nodes below might be unavailable if some plugin is disabled.
	DpdkCryptoInput = "dpdk-crypto-input"
	DpdkInput       = "dpdk-input"
	HandoffTrace    = "handoff-trace"
	IxgeInput       = "ixge-input"
	MrvlPp2Input    = "mrvl-pp2-input"
	NetmapInput     = "netmap-input"
)

var (
	CommonNodes = []string{
		AfPacketInput,
		MemifInput,
		TuntapRx,
		VirtioInput,
	}
	GenericNodes = []string{
		AfPacketInput,
		AvfInput,
		BondProcess,
		MemifInput,
		P2pEthernetInput,
		PgInput,
		PuntSocketRx,
		RdmaInput,
		SessionQueue,
		TuntapRx,
		VhostUserInput,
		VirtioInput,
		Vmxnet3Input,
	}
	OptionalNodes = []string{
		DpdkCryptoInput,
		DpdkInput,
		HandoffTrace,
		IxgeInput,
		MrvlPp2Input,
		NetmapInput,
	}
)
