package local

import (
	"fmt"
	"os/exec"
	"strings"

	"git.fd.io/govpp.git"
	"git.fd.io/govpp.git/adapter/statsclient"
	govppapi "git.fd.io/govpp.git/api"
	govppcore "git.fd.io/govpp.git/core"

	"go.ligato.io/vpp-probe/probe"
	"go.ligato.io/vpp-probe/providers"
	vppcli "go.ligato.io/vpp-probe/vpp/cli"
)

// HandlerConfig defines config parameters for Handler.
type HandlerConfig struct {
	PreferVppctl bool
	CliAddr      string
	BinapiAddr   string
	StatsAddr    string
}

// DefaultConfig returns config set to default values.
func DefaultConfig() HandlerConfig {
	return HandlerConfig{
		PreferVppctl: false,
		CliAddr:      "/run/vpp/cli.sock",
		BinapiAddr:   "/run/vpp/api.sock",
		StatsAddr:    "/run/vpp/stats.sock",
	}
}

// NewHandler returns a new handler for a local instance.
type Handler struct {
	HandlerConfig

	pid int

	binapiConn *govppcore.Connection
	statsConn  *govppcore.StatsConnection
}

// NewHandler returns a new handler for a local instance.
func NewHandler(pid int, config HandlerConfig) *Handler {
	return &Handler{
		pid:           pid,
		HandlerConfig: config,
	}
}

func (h *Handler) ID() string {
	return fmt.Sprintf("pid-%d", h.pid)
}

func (h *Handler) Metadata() map[string]string {
	return map[string]string{
		"env": providers.Local,
		"pid": fmt.Sprint(h.pid),
	}
}

func (h *Handler) ExecCmd(cmd string, args ...string) (string, error) {
	c := exec.Command(cmd, args...)
	out, err := c.Output()
	if err != nil {
		return string(out), err
	}
	return strings.TrimSpace(string(out)), err
}

func (h *Handler) GetCLI() (probe.CliExecutor, error) {
	var cli vppcli.Executor
	if h.PreferVppctl || h.CliAddr == "" {
		cli = vppcli.VppCtl
	} else {
		cli = vppcli.VppCtlAddr(h.CliAddr)
	}
	return cli, nil
}

func (h *Handler) GetAPI() (govppapi.Channel, error) {
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

func (h *Handler) GetStats() (govppapi.StatsProvider, error) {
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

func (h *Handler) Close() error {
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
