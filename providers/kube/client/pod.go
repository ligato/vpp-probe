package client

import (
	"bytes"
	"fmt"
	"io"
	"time"

	"github.com/sirupsen/logrus"
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
	ImageID   string
	HostNetwork bool

	pod    *corev1.Pod
	client *Client
	Node   *corev1.Node
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
		ImageID:   getPodFirstContainerStatus(pod).ImageID,
		HostNetwork: pod.Spec.HostNetwork,
		pod:       pod,
		client:    client,
	}
}

// Strings returns name for this pod prefixed with cluster name and namespace.
func (pod Pod) String() string {
	return fmt.Sprintf("%s::%s", pod.Namespace, pod.Name)
}

// Age returns duration since the pod started.
func (pod Pod) Age() time.Duration {
	if pod.Created.IsZero() {
		return -1
	}
	return time.Since(pod.Created)
}

// PortForward starts port forwarding of pod port to a local random port.
func (pod Pod) PortForward(podPort int) (*PortForwarder, error) {
	return PortForward(pod.client, PortForwardOptions{
		PodName:      pod.Name,
		PodNamespace: pod.Namespace,
		LocalPort:    0, // pick random
		PodPort:      podPort,
	})
}

// Exec executes a command in the pod.
func (pod Pod) Exec(command string, stdin io.Reader, stdout, stderr io.Writer) error {
	container := getPodFirstContainer(pod.pod).Name
	return pod.ExecContainer(container, command, stdin, stdout, stderr)
}

func getPodFirstContainer(pod *corev1.Pod) corev1.Container {
	if len(pod.Spec.Containers) == 0 {
		return corev1.Container{}
	}
	return pod.Spec.Containers[0]
}

func getPodFirstContainerStatus(pod *corev1.Pod) corev1.ContainerStatus {
	if len(pod.Status.ContainerStatuses) == 0 {
		return corev1.ContainerStatus{}
	}
	return pod.Status.ContainerStatuses[0]
}

// ExecContainer executes a command in a container of the pod.
func (pod Pod) ExecContainer(container, command string, stdin io.Reader, stdout, stderr io.Writer) error {
	return podExec(pod.client, pod.Namespace, pod.Name, container, command, stdin, stdout, stderr)
}

// podExec exec command on specific pod and wait the command's output.
func podExec(client *Client, namespace, podName, container string,
	cmd string, stdin io.Reader, stdout, stderr io.Writer,
) error {
	opts := &corev1.PodExecOptions{
		Container: container,
		Command:   []string{"sh", "-c", cmd},
		Stdin:     stdin != nil,
		Stdout:    stdout != nil,
		Stderr:    true,
		TTY:       false,
	}
	req := client.client.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(podName).
		Namespace(namespace).
		SubResource("exec").
		VersionedParams(opts, scheme.ParameterCodec)

	logrus.WithFields(logrus.Fields{
		"command":   opts.Command,
		"container": opts.Container,
	}).Tracef("pod %s running exec: %+v", podName, req.URL())

	exec, err := remotecommand.NewSPDYExecutor(client.restConfig, "POST", req.URL())
	if err != nil {
		return err
	}
	if stderr == nil {
		stderr = new(bytes.Buffer)
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
