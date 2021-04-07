package api

import (
	"time"
)

type (
	VppInfo struct {
		Build   BuildInfo
		System  SystemInfo
		Plugins []PluginInfo `json:",omitempty"`
	}

	BuildInfo struct {
		Version       string
		BuildUser     string    `json:",omitempty"`
		BuildHost     string    `json:",omitempty"`
		BuildDate     time.Time `json:",omitempty"`
		BuildLocation string    `json:",omitempty"`
		Compiler      string    `json:",omitempty"`
	}

	SystemInfo struct {
		Pid    int
		Uptime time.Duration `json:",omitempty"`
		Clock  time.Time     `json:",omitempty"`
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
