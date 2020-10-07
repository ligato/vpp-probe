package localprobe

import (
	"fmt"
	"os/exec"
	"strings"

	"git.fd.io/govpp.git"
	"git.fd.io/govpp.git/adapter/statsclient"
	govppapi "git.fd.io/govpp.git/api"
	govppcore "git.fd.io/govpp.git/core"
	"github.com/sirupsen/logrus"

	"go.ligato.io/vpp-probe/pkg/vppcli"
)

type Handler struct {
	CliAddr    string
	BinapiAddr string
	StatsAddr  string

	binapiConn *govppcore.Connection
	statsConn  *govppcore.StatsConnection
}

// NewHandler returns new handler for a pod.
func NewHandler() *Handler {
	return &Handler{
		CliAddr:    "",
		BinapiAddr: "",
		StatsAddr:  "",
	}
}

func (l *Handler) Name() string {
	return fmt.Sprintf("local")
}

func (l *Handler) ExecCmd(cmd string, args ...string) (string, error) {
	c := exec.Command(cmd, args...)
	out, err := c.Output()
	if err != nil {
		return string(out), err
	}
	return strings.TrimSpace(string(out)), err
}

func (l *Handler) GetCLI() (vppcli.Executor, error) {
	if l.CliAddr == "" {
		return vppcli.VppCtl, nil
	}
	return vppcli.VppCtlAddr(l.CliAddr), nil
}

func (l *Handler) GetAPI() (govppapi.Channel, error) {
	if l.binapiConn == nil {
		conn, err := govpp.Connect(l.BinapiAddr)
		if err != nil {
			return nil, fmt.Errorf("connecting to VPP failed: %v", err)
		}
		l.binapiConn = conn
	}

	ch, err := l.binapiConn.NewAPIChannel()
	if err != nil {
		logrus.Fatalln("ERROR: creating channel:", err)
	}
	return ch, nil
}

func (l *Handler) GetStats() (govppapi.StatsProvider, error) {
	if l.statsConn == nil {
		statsAdapter := statsclient.NewStatsClient(l.StatsAddr)
		conn, err := govppcore.ConnectStats(statsAdapter)
		if err != nil {
			return nil, fmt.Errorf("connecting to VPP failed: %v", err)
		}
		l.statsConn = conn
	}

	return l.statsConn, nil
}

func (l *Handler) Close() error {
	if l.binapiConn != nil {
		l.binapiConn.Disconnect()
		l.binapiConn = nil
	}
	if l.statsConn != nil {
		l.statsConn.Disconnect()
		l.statsConn = nil
	}
	return nil
}
