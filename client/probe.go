package client

type (
	// VersionInfo contains VPP version info.
	VersionInfo struct {
		Version string
		Pid     int
	}

	// RuntimeInfo contains VPP runtime info.
	RuntimeInfo struct {
		Clock string
	}
)

type (
	// Interface defines an interface configured in VPP.
	Interface struct {
		Index uint32
		Name  string
		Tag   string

		Type    string
		DevType string

		State string

		MAC  string
		MTUs MTU
		IPs  []string
		VRF  VRF
	}

	// MTU groups MTU setting for an interface.
	MTU struct {
		L3       uint
		IP4, IP6 uint
		MPLS     uint
		Link     uint
	}

	// VRF groups VRF table setting for interface.
	VRF struct {
		IP4, IP6 uint
	}
)

type Probe interface {
	ID() string
	VersionInfo() (*VersionInfo, error)
	ListInterfaces() ([]*Interface, error)
	GetClock() (string, error)
	DumpLogs() ([]string, error)
}
