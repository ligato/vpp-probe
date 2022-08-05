package client

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/sirupsen/logrus"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/transport/spdy"
)

type PortForwardOptions struct {
	PodName      string
	PodNamespace string
	PodPort      int
	LocalPort    int
}

type PortForwarder struct {
	Streams genericclioptions.IOStreams

	portFwd *portforward.PortForwarder
	ports   []portforward.ForwardedPort
	stopCh  chan struct{}
	doneCh  <-chan error
}

// PortForward starts port forwarding for a port and returns the PortForwarder.
func PortForward(client *Client, opt PortForwardOptions) (*PortForwarder, error) {
	var port string
	if opt.LocalPort == 0 {
		port = fmt.Sprintf(":%d", opt.PodPort)
	} else {
		port = fmt.Sprintf("%d:%d", opt.LocalPort, opt.PodPort)
	}

	path := fmt.Sprintf("/api/v1/namespaces/%s/pods/%s/portforward", opt.PodNamespace, opt.PodName)
	hostIP := strings.TrimLeft(client.restConfig.Host, "htps:/")

	log := logrus.WithFields(map[string]interface{}{
		"pod":       opt.PodName,
		"namespace": opt.PodNamespace,
		"cluster":   client.Cluster(),
		"port":      port,
	})

	transport, upgrader, err := spdy.RoundTripperFor(client.restConfig)
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
		var err error

		defer log.Tracef("stopped forwarding ports (err: %v)", err)

		defer func() {
			if e := recover(); e != nil {
				err = fmt.Errorf("recovered panic: %v", e)
			}
			errCh <- err
		}()

		if err = fw.ForwardPorts(); err != nil {
			log.Debugf("ForwardPorts error: %v", err)
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

	log.Debugf("started forwarding ports: %+v", ports)

	return &PortForwarder{
		Streams: streams,
		portFwd: fw,
		ports:   ports,
		stopCh:  stopCh,
		doneCh:  errCh,
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
	pf.doneCh = nil
}

func (pf *PortForwarder) Done() <-chan error {
	return pf.doneCh
}
