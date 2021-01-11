// Package probe defines an API to manage probe instances.
package probe

import (
	govppapi "git.fd.io/govpp.git/api"
)

// Provider provides ways to discover instances.
type Provider interface {
	// Env returns the environment type of the provider.
	Env() string

	// Name returns a name of the provider.
	Name() string

	// Query runs query with list of parameters used as filters and returns a list
	// of Handler for
	Query(params ...map[string]string) ([]Handler, error)
}

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
	// ExecCmd executes a command in the OS where the instance is running.
	ExecCmd(cmd string, args ...string) (string, error)
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
