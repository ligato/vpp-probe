package e2e

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"

	"go.ligato.io/vpp-probe/client"
	"go.ligato.io/vpp-probe/cmd"
	"go.ligato.io/vpp-probe/probe"
	"go.ligato.io/vpp-probe/providers/kube"
	"go.ligato.io/vpp-probe/vpp"
)

func TestBasicTestSuite(t *testing.T) {
	suite.Run(t, &BasicTestSuite{
		E2ETestSuite: E2ETestSuite{
			resourcesDir: "./resources",
			clusters:     []string{*cluster1},
		},
	})
}

type BasicTestSuite struct {
	E2ETestSuite
}

func (s *BasicTestSuite) SetupSuite() {
	// setup topology
	kubectl(s.T(), s.kubectx(0), "apply", "-f", filepath.Join(s.resourcesDir, "vnf.yml"))
	time.Sleep(time.Second * 5)
	kubectl(s.T(), s.kubectx(0), "wait", "--for=condition=Ready", "pod/vpp-vnf1", "pod/vpp-vnf2", "pod/vpp-vswitch", fmt.Sprintf("--timeout=%v", waitPodReady))

	// copy configs to containers
	kubectl(s.T(), s.kubectx(0), "cp", filepath.Join(s.resourcesDir, "vnf1-config.yml"), "vpp-vnf1:/")
	kubectl(s.T(), s.kubectx(0), "cp", filepath.Join(s.resourcesDir, "vnf2-config.yml"), "vpp-vnf2:/")
	kubectl(s.T(), s.kubectx(0), "cp", filepath.Join(s.resourcesDir, "vswitch-config.yml"), "vpp-vswitch:/")
}

func (s *BasicTestSuite) TearDownSuite() {
	// teardown topology
	kubectl(s.T(), s.kubectx(0), "delete", "-f", filepath.Join(s.resourcesDir, "vnf.yml"))
}

func (s *BasicTestSuite) SetupTest() {
	// configure VPPs
	kubectl(s.T(), s.kubectx(0), "exec", "-i", "vpp-vnf1", "--", "agentctl", "config", "update", "--replace", "/vnf1-config.yml")
	kubectl(s.T(), s.kubectx(0), "exec", "-i", "vpp-vnf2", "--", "agentctl", "config", "update", "--replace", "/vnf2-config.yml")
	kubectl(s.T(), s.kubectx(0), "exec", "-i", "vpp-vswitch", "--", "agentctl", "config", "update", "--replace", "/vswitch-config.yml")
}

func (s *BasicTestSuite) TearDownTest() {
	// cleanup after test
}

func (s *BasicTestSuite) TestQuery() {
	t := s.T()

	p, err := kube.NewProvider("", s.kubectx(0))
	if err != nil {
		t.Fatal(err)
	}

	c, err := client.NewClient()
	if err != nil {
		t.Fatal(err)
	}
	if err := c.AddProvider(p); err != nil {
		t.Fatal(err)
	}

	s.Run("empty query", func() {
		handlers, err := p.Query()
		if s.NoError(err) {
			s.NotEmpty(handlers)
		}
	})

	var handlers []probe.Handler
	s.Run("query label", func() {
		handlers, err = p.Query(map[string]string{"label": "app=vpp"})
		if s.NoError(err) {
			s.Len(handlers, 3)
		}
	})

	s.Run("init instances", func() {
		var vpps []*vpp.Instance
		for _, h := range handlers {
			t.Logf("- %v: %+v", h.ID(), h.Metadata())
			instance, err := vpp.NewInstance(h)
			if err != nil {
				continue
			}
			vpps = append(vpps, instance)
			t.Logf("instance: %+v", instance)
		}
		s.Len(vpps, 3)
	})
}

func (s *BasicTestSuite) TestDiscover() {
	cli := s.setupProbeCli()

	discOpts := cmd.DiscoverOptions{
		IPsecAgg: true,
	}
	err := cmd.RunDiscover(cli, discOpts)
	s.NoError(err)
}

func (s *BasicTestSuite) TestTracer() {
	cli := s.setupProbeCli()

	tracerOpts := cmd.DefaultTraceOptions
	tracerOpts.CustomCmd = fmt.Sprintf(
		"kubectl --context=%s exec -i %s -- ping -c 1 %s", s.kubectx(0), "vpp-vswitch", "192.168.23.2",
	)

	err := cmd.RunTrace(cli, tracerOpts)
	s.NoError(err)
}

func (s *BasicTestSuite) TestTopology() {
	cli := s.setupProbeCli()

	topoOpts := cmd.TopologyOptions{}

	err := cmd.RunTopology(cli, topoOpts)
	s.NoError(err)
}
