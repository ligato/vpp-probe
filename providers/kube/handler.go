package kube

import (
	"fmt"
	"strings"

	govppapi "git.fd.io/govpp.git/api"
	"git.fd.io/govpp.git/proxy"
	"github.com/sirupsen/logrus"

	"go.ligato.io/vpp-probe/probe"
	"go.ligato.io/vpp-probe/providers/kube/client"
	vppcli "go.ligato.io/vpp-probe/vpp/cli"
)

const defaultHttpPort = 9191

// Handler is used to manage an instance running in Kubernetes.
type Handler struct {
	pod *client.Pod

	vppProxy  *proxy.Client
	portFwder *client.PortForwarder
}

// NewHandler returns a new handler for an instance running in a pod.
func NewHandler(pod *client.Pod) *Handler {
	return &Handler{
		pod: pod,
	}
}

func (h *Handler) ID() string {
	return fmt.Sprintf("%s/%s/%s", h.pod.Cluster, h.pod.Namespace, h.pod.Name)
}

func (h *Handler) ExecCmd(cmd string, args ...string) (string, error) {
	return h.podExec(cmd + " " + strings.Join(args, " "))
}

func (h *Handler) podExec(cmd string) (string, error) {
	out, err := h.pod.Exec(cmd)
	if err != nil {
		return "", fmt.Errorf("pod %v exec error: %v", h.pod.Name, err)
	}
	return strings.TrimSpace(out), nil
}

func (h *Handler) GetCLI() (probe.CliExecutor, error) {
	cli := vppcli.ExecutorFunc(func(cmd string) (string, error) {
		pod := h.pod
		command := `vppctl "` + cmd + `"`
		out, err := pod.Exec(command)
		if err != nil {
			return "", fmt.Errorf("pod %v exec error: %v", pod.Name, err)
		}
		return strings.TrimSpace(out), nil
	})
	return cli, nil
}

func (h *Handler) GetAPI() (govppapi.Channel, error) {
	if err := h.connectProxy(); err != nil {
		return nil, err
	}

	return proxyBinapi(h.vppProxy)
}

func (h *Handler) GetStats() (govppapi.StatsProvider, error) {
	if err := h.connectProxy(); err != nil {
		return nil, err
	}

	return proxyStats(h.vppProxy)
}

func (h *Handler) Close() error {
	h.vppProxy = nil
	if h.portFwder != nil {
		h.portFwder.Stop()
	}
	return nil
}

func (h *Handler) connectProxy() error {
	if h.vppProxy != nil {
		return nil
	}

	logrus.Debugf("forwarding ports for pod %v", h.pod)

	// start port forwarding to HTTP server on agent
	portFwder, err := h.pod.PortForward(defaultHttpPort)
	if err != nil {
		return fmt.Errorf("port forwarding failed: %v", err)
	}
	h.portFwder = portFwder
	logrus.Debugf("forwarded local port: %+v", portFwder.LocalPort())

	addr := fmt.Sprintf(":%d", portFwder.LocalPort())
	logrus.Debugf("connecting to proxy %v", addr)

	// connect to VPP proxy via HTTP server (go RPC)
	c, err := proxy.Connect(addr)
	if err != nil {
		h.portFwder.Stop()
		h.portFwder = nil
		return fmt.Errorf("connecting to proxy failed: %v", err)
	}

	h.vppProxy = c

	return nil
}

func proxyBinapi(client *proxy.Client) (*proxy.BinapiClient, error) {
	binapiChannel, err := client.NewBinapiClient()
	if err != nil {
		logrus.Warnf("creating new proxy binapi client failed: %v", err)
		return nil, err
	}

	return binapiChannel, nil
}

func proxyStats(client *proxy.Client) (*proxy.StatsClient, error) {
	statsProvider, err := client.NewStatsClient()
	if err != nil {
		logrus.Warnf("creating new proxy stats client failed: %v", err)
		return nil, err
	}
	return statsProvider, nil
}
