package client

import (
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/types"
)

// Pod is a pod returned from Client.
type Pod struct {
	UID       types.UID
	Name      string
	Cluster   string
	Node      string
	Namespace string
	IP        string
	Created   time.Time
	URL       string
	Image     string

	client *Client
}

// Strings returns name for this pod prefixed with cluster name and namespace.
func (p Pod) String() string {
	return fmt.Sprintf("%s::%s", p.Namespace, p.Name)
}

// Age returns duration since the pod started.
func (p Pod) Age() time.Duration {
	return time.Since(p.Created).Round(time.Second)
}

// PortForward starts port forwarding of pod port to a local random port.
func (p Pod) PortForward(podPort int) (*PortForwarder, error) {
	return p.client.PortForward(PortForwardOptions{
		PodName:      p.Name,
		PodNamespace: p.Namespace,
		LocalPort:    0, // pick random
		PodPort:      podPort,
	})
}

// Exec executes a command in the pod.
func (p Pod) Exec(command string) (string, error) {
	return p.ExecContainer("", command)
}

// ExecContainer executes a command in a container of the pod.
func (p Pod) ExecContainer(container, command string) (string, error) {
	return p.client.Exec(p.Namespace, p.Name, container, command)
}
