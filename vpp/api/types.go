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
)
