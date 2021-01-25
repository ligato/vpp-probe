package docker

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"time"

	govppapi "git.fd.io/govpp.git/api"
	"git.fd.io/govpp.git/proxy"
	docker "github.com/fsouza/go-dockerclient"
	"github.com/sirupsen/logrus"

	"go.ligato.io/vpp-probe/probe"
	"go.ligato.io/vpp-probe/providers"
	vppcli "go.ligato.io/vpp-probe/vpp/cli"
)

// Handler is used to manage an instance running in Docker.
type Handler struct {
	client    *docker.Client
	container *docker.Container

	vppProxy *proxy.Client
}

// NewHandler returns a new handler for an instance running in a pod.
func NewHandler(client *docker.Client, container *docker.Container) *Handler {
	return &Handler{
		client:    client,
		container: container,
	}
}

func (h *Handler) ID() string {
	containerName := strings.TrimPrefix(h.container.Name, "/")
	containerID := h.container.ID
	if len(containerID) > 7 {
		containerID = containerID[:7]
	}
	return fmt.Sprintf("%v-%v", containerName, containerID)
}

func (h *Handler) Metadata() map[string]string {
	id := h.container.ID
	if len(id) > 12 {
		id = h.container.ID[:12]
	}
	return map[string]string{
		"env":       providers.Docker,
		"name":      h.container.Name,
		"container": h.container.Name,
		"id":        id,
		"image":     h.container.Image,
		"created":   h.container.Created.Format(time.UnixDate),
	}
}

func (h *Handler) Close() error {
	logrus.Debugf("closing handler %v", h.ID())
	h.vppProxy = nil
	return nil
}

func (h *Handler) ExecCmd(cmd string, args ...string) (string, error) {
	command := cmd + " " + strings.Join(args, " ")
	return h.execCmd(h.container.ID, command, false)
}

func (h *Handler) GetCLI() (probe.CliExecutor, error) {
	arg := ""
	if _, err := h.ExecCmd("ls", "/run/vpp/cli.sock"); err != nil {
		logrus.Debugf("checking cli socket error: %v", err)
		arg = "-s localhost:5002"
		logrus.Debugf("using flag '%s' for vppctl", arg)
	}
	cli := vppcli.ExecutorFunc(func(cmd string) (string, error) {
		command := `vppctl ` + arg + ` "` + cmd + `"`
		out, err := h.execCmd(h.container.ID, command, false)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(out), nil
	})
	return cli, nil
}

func (h *Handler) execCmd(containerID string, command string, withStderr bool) (string, error) {
	createOpts := docker.CreateExecOptions{
		AttachStdin:  false,
		AttachStdout: true,
		AttachStderr: true,
		Tty:          false,
		Env:          nil,
		Cmd:          []string{"sh", "-c", command},
		Container:    containerID,
		User:         "",
		WorkingDir:   "",
		Context:      nil,
		Privileged:   false,
	}
	exec, err := h.client.CreateExec(createOpts)
	if err != nil {
		return "", err
	}
	var stdout, stderr bytes.Buffer
	startOpts := docker.StartExecOptions{
		InputStream:  nil,
		OutputStream: &stdout,
		ErrorStream:  &stderr,
		Detach:       false,
		Tty:          false,
		RawTerminal:  false,
		Success:      nil,
		Context:      nil,
	}
	if withStderr {
		startOpts.ErrorStream = io.MultiWriter(&stderr, &stdout)
	}
	if err := h.client.StartExec(exec.ID, startOpts); err != nil {
		return "", err
	}
	exe, err := h.client.InspectExec(exec.ID)
	if err != nil {
		return "", err
	}
	if exe.ExitCode != 0 {
		return stdout.String(), fmt.Errorf("docker exec cmd '%s' failed (exit code %d)\n%s", command, exe.ExitCode, stderr.String())
	}
	return stdout.String(), nil
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

func (h *Handler) connectProxy() error {
	if h.vppProxy != nil {
		return nil
	}

	logrus.Tracef("network settings: %+v", h.container.NetworkSettings)

	var ipaddr string
	for _, nw := range h.container.NetworkSettings.Networks {
		if nw.IPAddress != "" {
			ipaddr = nw.IPAddress
			break
		}
	}
	addr := fmt.Sprintf("%s:%d", ipaddr, 9191)

	logrus.Debugf("connecting to proxy %v", addr)

	c, err := proxy.Connect(addr)
	if err != nil {
		return fmt.Errorf("connecting to proxy failed: %v", err)
	}
	h.vppProxy = c

	return nil
}

func proxyBinapi(client *proxy.Client) (govppapi.Channel, error) {
	binapiChannel, err := client.NewBinapiClient()
	if err != nil {
		logrus.Errorf("creating new proxy binapi client failed: %v", err)
		return nil, err
	}
	return binapiChannel, nil
}

func proxyStats(client *proxy.Client) (govppapi.StatsProvider, error) {
	statsProvider, err := client.NewStatsClient()
	if err != nil {
		return nil, err
	}
	return statsProvider, nil
}
