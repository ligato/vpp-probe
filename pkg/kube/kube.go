package kube

import (
	"bytes"
	"context"
	"fmt"
	"io"

	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"
	"k8s.io/client-go/tools/remotecommand"
)

type KubeCtx struct {
	*api.Config
	client kubernetes.Interface
	config *restclient.Config
}

func NewKubeCtx(kubeconfig string) (*KubeCtx, error) {
	apicfg, err := clientcmd.LoadFromFile(kubeconfig)
	if err != nil {
		return nil, err
	}
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return nil, err
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	return &KubeCtx{
		Config: apicfg,
		client: clientset,
		config: config,
	}, nil
}

func (k *KubeCtx) Clientset() kubernetes.Interface {
	return k.client
}

type PodQuery struct {
	Namespace string
	Label     string
}

func (q PodQuery) String() string {
	s := fmt.Sprintf("Label=%q ", q.Label)
	if q.Namespace != "" {
		s += fmt.Sprintf("Namespace=%q", q.Namespace)
	} else {
		s += fmt.Sprintf("Namespace=ALL")
	}
	return s
}

func (k *KubeCtx) FindPods(queries []PodQuery) (list []corev1.Pod) {
	for _, q := range queries {
		logrus.Debugf("-> pod query: %+v", q)

		pods, err := k.client.CoreV1().Pods(q.Namespace).List(context.TODO(), metav1.ListOptions{
			LabelSelector: q.Label,
		})
		if err != nil {
			logrus.Warnf("listing pods failed: %v", err)
			continue
		}
		logrus.Debugf("queried %d pods", len(pods.Items))
		for _, pod := range pods.Items {
			list = append(list, pod)
		}
	}
	return
}

func (k *KubeCtx) Exec(namespace, pod, container, command string) (string, error) {
	var out bytes.Buffer
	err := execCmd(k.client, k.config, namespace, pod, container, command, nil, &out, &out)
	if err != nil {
		return "", err
	}
	return out.String(), nil
}

// ExecCmd exec command on specific pod and wait the command's output.
func execCmd(client kubernetes.Interface, config *restclient.Config, namespace, podName, container string,
	command string, stdin io.Reader, stdout io.Writer, stderr io.Writer) error {
	req := client.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(podName).
		Namespace(namespace).
		SubResource("exec").
		Param("container", container)
	req.VersionedParams(&corev1.PodExecOptions{
		Container: container,
		Command:   []string{"sh", "-c", command},
		Stdin:     stdin != nil,
		Stdout:    true,
		Stderr:    true,
		TTY:       true,
	}, scheme.ParameterCodec)

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
