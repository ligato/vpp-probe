package local

import (
	"fmt"

	"git.fd.io/govpp.git"
	"git.fd.io/govpp.git/adapter/statsclient"
	govppapi "git.fd.io/govpp.git/api"
	govppcore "git.fd.io/govpp.git/core"

	"go.ligato.io/vpp-probe/pkg/exec"
	"go.ligato.io/vpp-probe/probe"
	"go.ligato.io/vpp-probe/providers"
	vppcli "go.ligato.io/vpp-probe/vpp/cli"
)

// HandlerConfig defines config parameters for ProcessHandler.
type HandlerConfig struct {
	CliAddr    string
	BinapiAddr string
	StatsAddr  string
}

// DefaultConfig returns config set to default values.
func DefaultConfig() HandlerConfig {
	return HandlerConfig{
		CliAddr:    "/run/vpp/cli.sock",
		BinapiAddr: "/run/vpp/api.sock",
		StatsAddr:  "/run/vpp/stats.sock",
	}
}

// ProcessHandler is a handler for local instance.
type ProcessHandler struct {
	HandlerConfig

	pid int

	binapiConn *govppcore.Connection
	statsConn  *govppcore.StatsConnection
}

// NewHandler returns a new handler for a local instance specified by PID.
func NewHandler(pid int, config HandlerConfig) *ProcessHandler {
	return &ProcessHandler{
		pid:           pid,
		HandlerConfig: config,
	}
}

func (h *ProcessHandler) ID() string {
	return fmt.Sprintf("process-%d", h.pid)
}

func (h *ProcessHandler) Metadata() map[string]string {
	return map[string]string{
		"env": providers.Local,
		"pid": fmt.Sprint(h.pid),
	}
}

func (h *ProcessHandler) Command(cmd string, args ...string) exec.Cmd {
	return exec.Command(cmd, args...)
}

func (h *ProcessHandler) GetCLI() (probe.CliExecutor, error) {
	wrapper := exec.Wrap(h, "/usr/bin/vppctl", "-s", h.CliAddr)
	cli := vppcli.ExecutorFunc(func(cmd string) (string, error) {
		out, err := wrapper.Command(cmd).Output()
		if err != nil {
			return "", err
		}
		return string(out), nil
	})
	return cli, nil
}

func (h *ProcessHandler) GetAPI() (govppapi.Channel, error) {
	if h.binapiConn == nil {
		conn, err := govpp.Connect(h.BinapiAddr)
		if err != nil {
			return nil, fmt.Errorf("connecting to API failed: %w", err)
		}
		h.binapiConn = conn
	}

	ch, err := h.binapiConn.NewAPIChannel()
	if err != nil {
		return nil, fmt.Errorf("creating API channel failed: %w", err)
	}
	return ch, nil
}

func (h *ProcessHandler) GetStats() (govppapi.StatsProvider, error) {
	if h.statsConn == nil {
		statsAdapter := statsclient.NewStatsClient(h.StatsAddr)
		conn, err := govppcore.ConnectStats(statsAdapter)
		if err != nil {
			return nil, fmt.Errorf("connecting to stats failed: %w", err)
		}
		h.statsConn = conn
	}

	return h.statsConn, nil
}

func (h *ProcessHandler) Close() error {
	if h.binapiConn != nil {
		h.binapiConn.Disconnect()
		h.binapiConn = nil
	}
	if h.statsConn != nil {
		h.statsConn.Disconnect()
		h.statsConn = nil
	}
	return nil
}
