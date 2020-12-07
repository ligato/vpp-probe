package client

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"

	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/version"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
	"k8s.io/klog"
)

func init() {
	klogger := logrus.StandardLogger()
	klogger.WithField("logger", "kube")
	klog.InitFlags(nil)
	klog.SetOutput(klogger.Writer())
	if err := flag.Set("logtostderr", "false"); err != nil {
		logrus.Error(err)
	}
	if err := flag.Set("alsologtostderr", "false"); err != nil {
		logrus.Error(err)
	}
	if err := flag.Set("stderrthreshold", "999"); err != nil {
		logrus.Error(err)
	}
}

// Client is a client for interacting with Kubernetes API for a single master.
type Client struct {
	config     *Config
	restConfig *restclient.Config
	client     kubernetes.Interface
}

// NewClient returns a new client loaded from configLoader with config overrides.
func NewClient(config *Config) (*Client, error) {
	clientConfig, err := config.ClientConfig()
	if err != nil {
		return nil, err
	}
	restConfig, err := clientConfig.ClientConfig()
	if err != nil {
		return nil, err
	}
	clientset, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return nil, err
	}
	return &Client{
		client:     clientset,
		config:     config,
		restConfig: restConfig,
	}, nil
}

func (k *Client) String() string {
	return fmt.Sprintf("%v", k.config.CurrentContext())
}

// Clientset returns interface for kubernetes API.
func (k *Client) Clientset() kubernetes.Interface {
	return k.client
}

// Cluster returns the cluster name used for this client.
func (k *Client) Cluster() string {
	ctx := k.config.GetContext()
	if ctx == nil {
		return ""
	}
	return ctx.Cluster
}

// Namespace returns the namspace name used for this client.
func (k *Client) Namespace() string {
	ctx := k.config.GetContext()
	if ctx == nil {
		return ""
	}
	return ctx.Namespace
}

func (k *Client) GetVersionInfo() (*version.Info, error) {
	info, err := k.client.Discovery().ServerVersion()
	if err != nil {
		return nil, err
	}
	return info, nil
}

// GetPod calls the API to get pod with namespace and name.
func (k *Client) GetPod(namespace string, name string) (*Pod, error) {
	if namespace == "" {
		namespace = k.Namespace()
	}
	pod, err := k.client.CoreV1().Pods(namespace).Get(context.TODO(), name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	return k.newPod(pod), nil
}

// ListPods calls the API to lists all pods with namespace and label selector.
func (k *Client) ListPods(namespace string, labelSelector, fieldSelector string) (list []*Pod, err error) {
	if namespace == "" {
		namespace = k.Namespace()
	}
	pods, err := k.client.CoreV1().Pods(namespace).List(context.TODO(), metav1.ListOptions{
		LabelSelector: labelSelector,
		FieldSelector: fieldSelector,
	})
	if err != nil {
		return nil, err
	}
	for _, p := range pods.Items {
		pod := k.newPod(&p)
		list = append(list, pod)
	}
	return list, nil
}

func (k *Client) newPod(p *corev1.Pod) *Pod {
	return &Pod{
		Cluster:   k.Cluster(),
		Name:      p.GetName(),
		Namespace: p.GetNamespace(),
		IP:        p.Status.PodIP,
		Created:   p.CreationTimestamp.Time,
		URL:       p.GetSelfLink(),
		client:    k,
	}
}

// Exec calls the API to execute a command in a container of a pod.
func (k *Client) Exec(namespace, pod, container, command string) (string, error) {
	var out bytes.Buffer
	err := execCmd(k.client, k.restConfig, namespace, pod, container, command, nil, &out, &out)
	if err != nil {
		return "", err
	}
	return out.String(), nil
}

// ExecCmd exec command on specific pod and wait the command's output.
func execCmd(client kubernetes.Interface, config *restclient.Config, namespace, podName, container string,
	command string, stdin io.Reader, stdout io.Writer, stderr io.Writer,
) error {
	cmd := []string{"sh", "-c", command}
	podExecOpts := &corev1.PodExecOptions{
		Container: container,
		Command:   cmd,
		Stdin:     stdin != nil,
		Stdout:    true,
		Stderr:    true,
		TTY:       true,
	}
	req := client.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(podName).
		Namespace(namespace).
		SubResource("exec").
		Param("container", container).
		VersionedParams(podExecOpts, scheme.ParameterCodec)

	exec, err := remotecommand.NewSPDYExecutor(config, "POST", req.URL())
	if err != nil {
		return err
	}
	err = exec.Stream(remotecommand.StreamOptions{
		Stdin:  stdin,
		Stdout: stdout,
		Stderr: stderr,
		Tty:    true,
	})
	if err != nil {
		return err
	}
	return nil
}
