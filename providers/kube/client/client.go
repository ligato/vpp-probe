package client

import (
	"context"
	"flag"
	"fmt"

	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/version"
	"k8s.io/client-go/kubernetes"
	restclient "k8s.io/client-go/rest"
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
	restConfig, err := config.RESTConfig()
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
	return fmt.Sprintf("%v", k.Context())
}

// Clientset returns interface for kubernetes API.
func (k *Client) Clientset() kubernetes.Interface {
	return k.client
}

// Cluster returns the cluster name used for this client.
func (k *Client) Context() string {
	ctx, err := k.config.CurrentContext()
	if err != nil {
		return ""
	}
	return ctx
}

// Cluster returns the cluster name used for this client.
func (k *Client) Cluster() string {
	cluster, err := k.config.CurrentCluster()
	if err != nil {
		return ""
	}
	return cluster
}

// Namespace returns the namspace name used for this client.
func (k *Client) Namespace() string {
	ns, err := k.config.CurrentNamespace()
	if err != nil {
		return ""
	}
	return ns
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
	if namespace == "" {
		namespace = "default"
	}
	pod, err := k.client.CoreV1().Pods(namespace).Get(context.TODO(), name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	return newPod(k, pod), nil
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
		if p.Namespace == "kube-system" {
			// ignore internal kubernetes pods
			continue
		}
		logrus.Tracef("pod %v:\n%+v", p.Name, p)
		pod := newPod(k, &p)
		list = append(list, pod)
	}
	return list, nil
}
