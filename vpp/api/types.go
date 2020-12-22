package api

import (
	"time"
)

type (
	VersionInfo struct {
		Version string
		Pid     int
	}

	SystemInfo struct {
		Clock time.Time
	}

	PluginInfo struct {
		Name        string
		Path        string
		Version     string
		Description string
	}
)

type (
	Interface struct {
		Index      uint32
		Name       string
		Tag        string
		Type       string
		DeviceType string
		Status     Status

		MAC  string
		MTUs MTU
		IPs  []string
		VRF  VRF
	}

	Status struct {
		Up   bool
		Link bool
	}

	MTU struct {
		L3       uint
		IP4, IP6 uint
		MPLS     uint
		Link     uint
	}

	VRF struct {
		IP4, IP6 uint
	}
)
