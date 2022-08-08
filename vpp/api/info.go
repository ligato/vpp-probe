package api

import (
	"time"
)

type (
	// VppInfo contains a generic information from VPP.
	VppInfo struct {
		Build   BuildInfo
		Runtime RuntimeInfo
		Plugins []Plugin `json:",omitempty"`
	}

	BuildInfo struct {
		Version       string
		BuildUser     string    `json:",omitempty"`
		BuildHost     string    `json:",omitempty"`
		BuildDate     time.Time `json:",omitempty"`
		BuildLocation string    `json:",omitempty"`
		Compiler      string    `json:",omitempty"`
	}

	RuntimeInfo struct {
		Pid    int
		Uptime Uptime     `json:",omitempty"`
		Clock  *time.Time `json:",omitempty"`
	}

	Plugin struct {
		Name        string
		Version     string
		Path        string `json:",omitempty"`
		Description string `json:",omitempty"`
	}
)

// Uptime is elapsed time in seconds since VPP started.
type Uptime uint64

func (uptime Uptime) MarshalText() (text []byte, err error) {
	return []byte(uptime.String()), nil
}

func (uptime Uptime) String() string {
	d := time.Duration(uptime) * time.Second
	return d.String()
}
