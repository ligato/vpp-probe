package client

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/deprecated/scheme"
	"k8s.io/client-go/tools/remotecommand"
)

type Cmd struct {
	Cmd  string
	Args []string

	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer

	pod *Pod
}

func (c *Cmd) SetStdin(in io.Reader) {
	c.Stdin = in
}

func (c *Cmd) SetStdout(out io.Writer) {
	c.Stdout = out
}

func (c *Cmd) SetStderr(out io.Writer) {
	c.Stderr = out
}

func (c *Cmd) Output() ([]byte, error) {
	if c.Stdout != nil {
		return nil, errors.New("stdout already set")
	}
	var stdout, stderr bytes.Buffer
	c.Stdout = &stdout

	captureErr := c.Stderr == nil
	if captureErr {
		c.Stderr = &stderr
	}

	err := c.Run()
	if err != nil && captureErr {
		err = fmt.Errorf("command error %w: %s", err, stderr.Bytes())
	}
	return stdout.Bytes(), err
}

func (c *Cmd) Run() error {
	command := fmt.Sprintf("%s %s", c.Cmd, strings.Join(c.Args, " "))
	container := getPodFirstContainer(c.pod.pod).Name

	return podExec(c.pod.client, c.pod.Namespace, c.pod.Name, container, command, c.Stdin, c.Stdout, c.Stderr)
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
