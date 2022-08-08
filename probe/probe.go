// Package probe defines an API to manage probe instances.
package probe

import (
	govppapi "git.fd.io/govpp.git/api"

	"go.ligato.io/vpp-probe/pkg/exec"
)

// Handler is an interface for handling a running instance.
type Handler interface {
	Host
	VPP

	// ID returns a string that identifies the handler.
	ID() string

	// Metadata returns a metadata for the handler.
	Metadata() map[string]string

	// Close closes open connections and frees resources used for this instance.
	Close() error
}

// Host is an interface for interacting with a host system where the instance is running.
type Host interface {
	// Command returns a command to be exectured on the host.
	Command(cmd string, args ...string) exec.Cmd
}

// VPP is an interface for interacting with a VPP instance.
type VPP interface {
	// GetCLI returns an executor for executing CLI commands.
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

// TODO
//  - add Metadata() to Host interface ?
//  - add more useful methods to Host ?
//    - for accessing filesystem
//    - network namespace
//  - remove VPP.GetCLI() ?
