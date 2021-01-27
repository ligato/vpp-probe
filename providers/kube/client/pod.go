package client

import (
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"

	"go.ligato.io/vpp-probe/internal/exec"
)

// Pod is a pod returned from Client.
type Pod struct {
	UID       types.UID
	Name      string
	NodeName  string
	Cluster   string
	Namespace string
	IP        string
	HostIP    string
	Created   time.Time
	URL       string
	Image     string

	pod    *corev1.Pod
	client *Client
}

func newPod(client *Client, pod *corev1.Pod) *Pod {
	return &Pod{
		Cluster:   client.Cluster(),
		UID:       pod.GetUID(),
		Name:      pod.GetName(),
		NodeName:  pod.Spec.NodeName,
		Namespace: pod.GetNamespace(),
		IP:        pod.Status.PodIP,
		HostIP:    pod.Status.HostIP,
		Created:   pod.GetCreationTimestamp().Time,
		URL:       pod.GetSelfLink(),
		Image:     getPodFirstContainer(pod).Image,
		pod:       pod,
		client:    client,
	}
}

// Strings returns name for this pod prefixed with cluster name and namespace.
func (p Pod) String() string {
	return fmt.Sprintf("%s::%s", p.Namespace, p.Name)
}

// Age returns duration since the pod started.
func (p Pod) Age() time.Duration {
	if p.Created.IsZero() {
		return -1
	}
	return time.Since(p.Created)
}

// PortForward starts port forwarding of pod port to a local random port.
func (p Pod) PortForward(podPort int) (*PortForwarder, error) {
	return PortForward(p.client, PortForwardOptions{
		PodName:      p.Name,
		PodNamespace: p.Namespace,
		LocalPort:    0, // pick random
		PodPort:      podPort,
	})
}

// Exec executes a command in the pod.
func (p Pod) Exec(command string) (string, error) {
	container := getPodFirstContainer(p.pod).Name
	return p.ExecContainer(container, command)
}

// ExecContainer executes a command in a container of the pod.
func (p Pod) ExecContainer(container, command string, args ...string) (string, error) {
	cmd := p.Command(command, args...)
	out, err := cmd.Output()
	return string(out), err
}

func (p Pod) Command(cmd string, args ...string) exec.Cmd {
	c := &Cmd{
		Cmd:  cmd,
		Args: args,
		pod:  &p,
	}
	return c
}

func getPodFirstContainer(pod *corev1.Pod) corev1.Container {
	if len(pod.Spec.Containers) == 0 {
		return corev1.Container{}
	}
	return pod.Spec.Containers[0]
}
