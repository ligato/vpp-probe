// Package probe defines an API to manage probe instances.
package probe

import (
	govppapi "git.fd.io/govpp.git/api"

	"go.ligato.io/vpp-probe/internal/exec"
)

// Handler handles a running instance.
type Handler interface {
	Host
	VPP

	// ID returns a string that identifies the instance.
	ID() string

	// Metadata returns a map of metadata for the instance handler.
	Metadata() map[string]string

	// Close closes open connections and frees resources used for this instance.
	Close() error
}

// Host is a common interface to interact host system (OS).
type Host interface {
	// Command returns command to be executed on the host OS where the instance is running.
	//ExecCmd(cmd string, args ...string) (string, error)
	Command(cmd string, args ...string) exec.Cmd

	//exec.Interface
}

// VPP is a common interface to access VPP APIs.
type VPP interface {
	// GetCLI returns an executor for CLI commands.
	GetCLI() (CliExecutor, error)

	// GetAPI returns a channel for binary API requests.
	GetAPI() (govppapi.Channel, error)

	// GetStats returns a provider for stats data.
	GetStats() (govppapi.StatsProvider, error)
}

// CliExecutor defines method executing CLI commands.
type CliExecutor interface {
	RunCli(cmd string) (string, error)
}
