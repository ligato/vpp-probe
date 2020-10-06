package kube

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/transport/spdy"
)

type PortForwardOptions struct {
	PodName      string
	PodNamespace string
	LocalPort    int
	PodPort      int
}

type PortForwarder struct {
	Streams genericclioptions.IOStreams

	portFwd *portforward.PortForwarder
	ports   []portforward.ForwardedPort
	stopCh  chan struct{}
}

func (k *Client) PortForward(opt PortForwardOptions) (*PortForwarder, error) {
	path := fmt.Sprintf("/api/v1/namespaces/%s/pods/%s/portforward",
		opt.PodNamespace, opt.PodName)
	hostIP := strings.TrimLeft(k.restConfig.Host, "htps:/")

	var port string
	if opt.LocalPort == 0 {
		port = fmt.Sprintf(":%d", opt.PodPort)
	} else {
		port = fmt.Sprintf("%d:%d", opt.LocalPort, opt.PodPort)
	}

	transport, upgrader, err := spdy.RoundTripperFor(k.restConfig)
	if err != nil {
		return nil, err
	}

	dialer := spdy.NewDialer(upgrader, &http.Client{Transport: transport},
		http.MethodPost, &url.URL{Scheme: "https", Path: path, Host: hostIP})

	readyCh := make(chan struct{})
	stopCh := make(chan struct{})
	errCh := make(chan error, 1)
	streams, _, _, _ := genericclioptions.NewTestIOStreams()

	fw, err := portforward.New(dialer, []string{port}, stopCh, readyCh, streams.Out, streams.ErrOut)
	if err != nil {
		return nil, err
	}

	go func() {
		if err := fw.ForwardPorts(); err != nil {
			errCh <- err
			return
		}
	}()

	var ports []portforward.ForwardedPort
	select {
	case err := <-errCh:
		return nil, err
	case <-readyCh:
		if ports, err = fw.GetPorts(); err != nil {
			return nil, err
		}
	}

	return &PortForwarder{
		Streams: streams,
		portFwd: fw,
		ports:   ports,
		stopCh:  stopCh,
	}, nil
}

func (pf *PortForwarder) LocalPort() uint16 {
	if len(pf.ports) == 0 {
		return 0
	}
	return pf.ports[0].Local
}

func (pf *PortForwarder) Stop() {
	if pf.stopCh == nil {
		return
	}
	close(pf.stopCh)
	pf.stopCh = nil
}
