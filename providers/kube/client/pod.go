package client

import (
	"bytes"
	"fmt"
	"io"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/deprecated/scheme"
	"k8s.io/client-go/tools/remotecommand"
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

	client *Client
}

func newPod(k *Client, p *corev1.Pod) *Pod {
	img := ""
	if len(p.Status.ContainerStatuses) > 0 {
		img = p.Status.ContainerStatuses[0].Image
	}
	return &Pod{
		client:    k,
		Cluster:   k.Cluster(),
		UID:       p.GetUID(),
		Name:      p.GetName(),
		NodeName:  p.Spec.NodeName,
		Namespace: p.GetNamespace(),
		IP:        p.Status.PodIP,
		HostIP:    p.Status.HostIP,
		Created:   p.GetCreationTimestamp().Time,
		URL:       p.GetSelfLink(),
		Image:     img,
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
	return p.ExecContainer("", command)
}

// ExecContainer executes a command in a container of the pod.
func (p Pod) ExecContainer(container, command string) (string, error) {
	var stdout, stderr bytes.Buffer
	err := podExec(p.client, p.Namespace, p.Name, container, command, nil, &stdout, &stderr)
	if err != nil {
		return stderr.String(), err
	}
	return stdout.String(), nil
}

// podExec exec command on specific pod and wait the command's output.
func podExec(client *Client, namespace, podName, container string,
	command string, stdin io.Reader, stdout io.Writer, stderr io.Writer,
) error {
	podExecOpts := &corev1.PodExecOptions{
		Container: container,
		Command:   []string{"sh", "-c", command},
		Stdin:     stdin != nil,
		Stdout:    stdout != nil,
		Stderr:    stderr != nil,
		TTY:       false,
	}
	req := client.client.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(podName).
		Namespace(namespace).
		SubResource("exec").
		Param("container", container).
		VersionedParams(podExecOpts, scheme.ParameterCodec)

	exec, err := remotecommand.NewSPDYExecutor(client.restConfig, "POST", req.URL())
	if err != nil {
		return err
	}
	err = exec.Stream(remotecommand.StreamOptions{
		Stdin:  stdin,
		Stdout: stdout,
		Stderr: stderr,
		Tty:    false,
	})
	if err != nil {
		return err
	}
	return nil
}
