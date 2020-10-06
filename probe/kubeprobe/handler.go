package kubeprobe

import (
	"encoding/gob"
	"fmt"
	"strings"

	govppapi "git.fd.io/govpp.git/api"
	"git.fd.io/govpp.git/examples/binapi/interfaces"
	"git.fd.io/govpp.git/proxy"
	"github.com/sirupsen/logrus"
	"go.ligato.io/vpp-agent/v3/plugins/vpp/binapi"
	"go.ligato.io/vpp-agent/v3/plugins/vpp/binapi/vpp2001"
	"go.ligato.io/vpp-agent/v3/plugins/vpp/binapi/vpp2001/ip"
	"go.ligato.io/vpp-agent/v3/plugins/vpp/binapi/vpp2001/vpe"

	"go.ligato.io/vpp-probe/pkg/kube"
	"go.ligato.io/vpp-probe/pkg/vppcli"
)

// Handler is used to manage access to an instance running in Kubernetes Pod.
type Handler struct {
	Pod *kube.Pod

	vppProxy  *proxy.Client
	portFwder *kube.PortForwarder
}

// NewHandler returns new handler for a pod.
func NewHandler(pod *kube.Pod) *Handler {
	return &Handler{
		Pod: pod,
	}
}

func (l *Handler) Name() string {
	return fmt.Sprintf("%s::%s/%s", l.Pod.Cluster, l.Pod.Namespace, l.Pod.Name)
}

func (l *Handler) ExecCmd(cmd string, args ...string) (string, error) {
	cmd += " " + strings.Join(args, " ")
	out, err := l.Pod.Exec(cmd)
	if err != nil {
		return "", fmt.Errorf("pod %v exec error: %v", l.Pod.Name, err)
	}
	return strings.TrimSpace(out), nil
}

func (l *Handler) GetCLI() (vppcli.Handler, error) {
	cli := vppcli.HandlerFunc(func(cmd string) (string, error) {
		pod := l.Pod
		command := `vppctl "` + cmd + `"`
		out, err := pod.Exec(command)
		if err != nil {
			return "", fmt.Errorf("kube pod %v exec: %v", pod.Name, err)
		}
		return strings.TrimSpace(out), nil
	})
	return cli, nil
}

func (l *Handler) GetAPI() (govppapi.Channel, error) {
	if err := l.connectProxy(); err != nil {
		return nil, err
	}
	return proxyBinapi(l.vppProxy)
}

func (l *Handler) GetStats() (govppapi.StatsProvider, error) {
	if err := l.connectProxy(); err != nil {
		return nil, err
	}
	stats, err := proxyStats(l.vppProxy)
	if err != nil {
		return nil, err
	}
	return stats, nil
}

func (l *Handler) Close() error {
	l.vppProxy = nil
	if l.portFwder != nil {
		l.portFwder.Stop()
	}
	return nil
}

func (l *Handler) connectProxy() error {
	if l.vppProxy != nil {
		return nil
	}

	logrus.Debugf("forwarding ports for pod %v", l.Pod)
	portFwder, err := l.Pod.PortForward(9191)
	if err != nil {
		return fmt.Errorf("port forwarding failed: %v", err)
	}
	l.portFwder = portFwder
	logrus.Debugf("forwarded local port: %+v", portFwder.LocalPort())

	logrus.Debugf("connecting to proxy")
	client, err := proxy.Connect(fmt.Sprintf(":%d", portFwder.LocalPort()))
	if err != nil {
		return fmt.Errorf("connecting to proxy failed: %v", err)
	}

	l.vppProxy = client

	return nil
}

const vppVersion = vpp2001.Version

func proxyBinapi(client *proxy.Client) (govppapi.Channel, error) {
	binapiChannel, err := client.NewBinapiClient()
	if err != nil {
		logrus.Errorf("creating new proxy binapi client failed: %v", err)
		return nil, err
	}

	// All binapi messages must be registered to gob
	for _, msg := range binapi.Versions[vppVersion].AllMessages() {
		gob.Register(msg)
	}

	// Check compatibility with remote VPP version
	var msgs []govppapi.Message
	msgs = append(msgs, ip.AllMessages()...)
	msgs = append(msgs, interfaces.AllMessages()...)
	msgs = append(msgs, vpe.AllMessages()...)
	if err := binapiChannel.CheckCompatiblity(msgs...); err != nil {
		logrus.Errorf("compatibility check (VPP %v) failed: %v", vppVersion, err)
		return nil, err
	}
	logrus.Debugf("compatibility OK! (VPP %v)", vppVersion)

	return binapiChannel, nil
}

func proxyStats(client *proxy.Client) (govppapi.StatsProvider, error) {
	statsProvider, err := client.NewStatsClient()
	if err != nil {
		return nil, err
	}
	return statsProvider, nil
}
