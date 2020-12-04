package api

import (
	"time"
)

type VPP interface {
	// Runtime
	GetVersionInfo() (*VersionInfo, error)
	GetUptime() (time.Duration, error)
	// Version() (string, error)
	// PID() (int, error)
	// StartupConfig() (string, error)
	// Plugins() ([]string, error)

	// System
	// Clock() (time.Time, error)
	// CPU() (string, error)
	// Threads() (string, error)
	// Memory() (string, error)
	// UnixFiles() ([]string, error)

	GetLogs(since time.Time) ([]string, error)
	DumpLogs() ([]string, error)
	// ShowLog(LogFilter) ([]LogEntry, error)

	// Interfaces
	ListInterfaces() ([]*Interface, error)

	// Stats
	ListStats() ([]string, error)
	// GetCounter(counter string) (string, error)
	// GetInterfaceStats(iface string) (string, error)
}
