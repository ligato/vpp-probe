package probe

import (
	govppapi "git.fd.io/govpp.git/api"

	"go.ligato.io/vpp-probe/pkg/vppcli"
)

// InstanceProvider is a common interface for finding instances.
type Provider interface {
	Discover(query ...interface{}) ([]Handler, error)
}

// Handler is an interface for accessing probe instances.
type Handler interface {
	Name() string
	Close() error

	ExecCmd(cmd string, args ...string) (string, error)

	GetCLI() (vppcli.Executor, error)
	GetAPI() (govppapi.Channel, error)
	GetStats() (govppapi.StatsProvider, error)
}
