package api

import (
	"time"
)

type VPP interface {
	// --------------
	// Runtime
	// --------------

	GetBuildInfo() (*BuildInfo, error)
	GetSystemInfo() (*SystemInfo, error)
	GetUptime() (time.Duration, error)
	// StartupConfig() (string, error)
	// Plugins() ([]string, error)

	// System
	// --------------

	GetLogs(since time.Time) ([]string, error)
	DumpLogs() ([]string, error)
	// Clock() (time.Time, error)
	// CPU() (string, error)
	// Threads() (string, error)
	// Memory() (string, error)
	// UnixFiles() ([]string, error)
	// ShowLog(LogFilter) ([]LogEntry, error)

	// Interfaces
	// --------------

	ListInterfaces() ([]*Interface, error)

	// Stats
	// --------------

	ListStats() ([]string, error)
	// GetCounter(counter string) (string, error)
	// GetInterfaceStats(iface string) (string, error)
}
