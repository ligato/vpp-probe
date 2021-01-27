package local

import (
	"fmt"
	stdexec "os/exec"

	"git.fd.io/govpp.git"
	"git.fd.io/govpp.git/adapter/statsclient"
	govppapi "git.fd.io/govpp.git/api"
	govppcore "git.fd.io/govpp.git/core"

	"go.ligato.io/vpp-probe/internal/exec"
	"go.ligato.io/vpp-probe/probe"
	"go.ligato.io/vpp-probe/providers"
	vppcli "go.ligato.io/vpp-probe/vpp/cli"
)

// HandlerConfig defines config parameters for Handler.
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

// Handler is a handler for local instance.
type Handler struct {
	HandlerConfig

	pid int

	binapiConn *govppcore.Connection
	statsConn  *govppcore.StatsConnection
}

// NewHandler returns a new handler for a local instance specified by PID.
func NewHandler(pid int, config HandlerConfig) *Handler {
	return &Handler{
		pid:           pid,
		HandlerConfig: config,
	}
}

func (h *Handler) ID() string {
	return fmt.Sprintf("local-%d", h.pid)
}

func (h *Handler) Metadata() map[string]string {
	return map[string]string{
		"env": providers.Local,
		"pid": fmt.Sprint(h.pid),
	}
}

func (h *Handler) ExecCmd(command string, args ...string) (string, error) {
	cmd := h.Command(command, args...)
	out, err := cmd.Output()
	return string(out), err
}

func (h *Handler) Command(command string, args ...string) exec.Cmd {
	return &Cmd{
		Cmd: stdexec.Command(command, args...),
	}
}

func (h *Handler) GetCLI() (probe.CliExecutor, error) {
	wrapper := exec.Wrap(h, "/usr/bin/vppctl", "-s", h.CliAddr)
	cli := vppcli.ExecutorFunc(func(cmd string) (string, error) {
		out, err := wrapper.Command(cmd).Output()
		if err != nil {
			return "", err
		}
		return string(out), nil
	})
	/*var cli probe.CliExecutor
	if h.CliAddr == "" {
		cli = vppcli.NewCmdExecutor("/usr/bin/vppctl")
	} else {
		cli = vppcli.NewCmdExecutor("/usr/bin/vppctl", "-s", h.CliAddr)
	}*/
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
