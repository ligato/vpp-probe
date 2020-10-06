package probe

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

// Handler is an interface for accessing probe instances.
type Handler interface {
	Name() string
	Close() error

	ExecCmd(cmd string, args ...string) (string, error)

	GetCLI() (vppcli.Handler, error)
	GetAPI() (govppapi.Channel, error)
	GetStats() (govppapi.StatsProvider, error)
}

type LocalHandler struct {
	CliAddr    string
	BinapiAddr string
	StatsAddr  string

	binapiConn *govppcore.Connection
	statsConn  *govppcore.StatsConnection
}

func (l *LocalHandler) Name() string {
	return fmt.Sprintf("local")
}

func (l *LocalHandler) ExecCmd(cmd string, args ...string) (string, error) {
	c := exec.Command(cmd, args...)
	out, err := c.Output()
	if err != nil {
		return string(out), err
	}
	return strings.TrimSpace(string(out)), err
}

func (l *LocalHandler) GetCLI() (vppcli.Handler, error) {
	if l.CliAddr == "" {
		return vppcli.Local, nil
	}
	return vppcli.VppCtl(l.CliAddr), nil
}

func (l *LocalHandler) GetAPI() (govppapi.Channel, error) {
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

func (l *LocalHandler) GetStats() (govppapi.StatsProvider, error) {
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

func (l *LocalHandler) Close() error {
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
