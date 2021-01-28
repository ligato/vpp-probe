package kube

import (
	"fmt"
	"strings"
	"time"

	govppapi "git.fd.io/govpp.git/api"
	"git.fd.io/govpp.git/proxy"
	"github.com/sirupsen/logrus"

	"go.ligato.io/vpp-probe/internal/exec"
	"go.ligato.io/vpp-probe/probe"
	"go.ligato.io/vpp-probe/providers"
	"go.ligato.io/vpp-probe/providers/kube/client"
	vppcli "go.ligato.io/vpp-probe/vpp/cli"
)

const defaultHttpPort = 9191

// PodHandler is used to manage an instance running in Kubernetes.
type PodHandler struct {
	pod *client.Pod

	vppProxy  *proxy.Client
	portFwder *client.PortForwarder
}

// NewHandler returns a new handler for an instance running in a pod.
func NewHandler(pod *client.Pod) *PodHandler {
	return &PodHandler{
		pod: pod,
	}
}

func (h *PodHandler) ID() string {
	return fmt.Sprintf("%s/%s/%s", h.pod.Cluster, h.pod.Namespace, h.pod.Name)
}

func (h *PodHandler) Metadata() map[string]string {
	return map[string]string{
		"env":       providers.Kube,
		"pod":       h.pod.Name,
		"name":      h.pod.Name,
		"namespace": h.pod.Namespace,
		"cluster":   h.pod.Cluster,
		"node":      h.pod.NodeName,
		"ip":        h.pod.IP,
		"host_ip":   h.pod.HostIP,
		"image":     h.pod.Image,
		"uid":       string(h.pod.UID),
		"created":   h.pod.Created.Format(time.UnixDate),
	}
}

func (h *PodHandler) Command(cmd string, args ...string) exec.Cmd {
	return h.pod.Command(cmd, args...)
}

func (h *PodHandler) ExecCmd(cmd string, args ...string) (string, error) {
	return h.podExec(cmd + " " + strings.Join(args, " "))
}

func (h *PodHandler) podExec(cmd string) (string, error) {
	out, err := h.pod.Exec(cmd)
	if err != nil {
		return "", fmt.Errorf("kube exec error: %w", err)
	}
	return strings.TrimSpace(out), nil
}

func (h *PodHandler) GetCLI() (probe.CliExecutor, error) {
	var args []string
	if err := h.Command("ls", "/run/vpp/cli.sock").Run(); err != nil {
		args = append(args, "-s", "localhost:5002")
		logrus.Tracef("checking cli socket error: %v, using flag '%s' for vppctl", err, args)
	}
	wrapper := exec.Wrap(h, "/usr/bin/vppctl", args...)
	cli := vppcli.ExecutorFunc(func(cmd string) (string, error) {
		out, err := wrapper.Command(cmd).Output()
		if err != nil {
			return "", err
		}
		return string(out), nil
	})
	return cli, nil
}

func (h *PodHandler) GetAPI() (govppapi.Channel, error) {
	if err := h.connectProxy(); err != nil {
		return nil, err
	}

	return proxyBinapi(h.vppProxy)
}

func (h *PodHandler) GetStats() (govppapi.StatsProvider, error) {
	if err := h.connectProxy(); err != nil {
		return nil, err
	}

	return proxyStats(h.vppProxy)
}

func (h *PodHandler) Close() error {
	h.vppProxy = nil
	if h.portFwder != nil {
		h.portFwder.Stop()
	}
	return nil
}

func (h *PodHandler) connectProxy() error {
	if h.vppProxy != nil {
		return nil // proxy already running
	}

	logrus.Debugf("connecting to VPP proxy on pod %v", h.pod)

	// start port forwarding to HTTP server on agent
	portFwder, err := h.pod.PortForward(defaultHttpPort)
	if err != nil {
		return fmt.Errorf("port forwarding failed: %v", err)
	}
	h.portFwder = portFwder

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
