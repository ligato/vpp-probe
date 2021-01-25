package e2e

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"

	"go.ligato.io/vpp-probe/client"
	"go.ligato.io/vpp-probe/cmd"
	"go.ligato.io/vpp-probe/providers/kube"
	"go.ligato.io/vpp-probe/vpp"
)

func TestBasicTestSuite(t *testing.T) {
	suite.Run(t, &BasicTestSuite{
		E2ETestSuite{
			kubectx: "kind-c1",
		},
	})
}

type BasicTestSuite struct {
	E2ETestSuite
}

func (s *BasicTestSuite) SetupSuite() {
	// setup topology
	kubectl(s.T(), s.kubectx, "apply", "-f", "../resources/vnf.yml")
	time.Sleep(time.Second * 5)
	kubectl(s.T(), s.kubectx, "wait", "--for=condition=Ready", "pod/vpp-vnf1", "pod/vpp-vnf2", "pod/vpp-vswitch", "--timeout=90s")

	// copy configs to containers
	kubectl(s.T(), s.kubectx, "cp", "../resources/vnf1-config.yml", "vpp-vnf1:/")
	kubectl(s.T(), s.kubectx, "cp", "../resources/vnf2-config.yml", "vpp-vnf2:/")
	kubectl(s.T(), s.kubectx, "cp", "../resources/vswitch-config.yml", "vpp-vswitch:/")
}

func (s *BasicTestSuite) TearDownSuite() {
	// teardown topology
	runCmd(s.T(), "kubectl", "--context", "kind-c1", "delete", "-f", "../resources/vnf.yml")
}

func (s *BasicTestSuite) SetupTest() {
	// configure VPPs
	kubectl(s.T(), s.kubectx, "exec", "-i", "vpp-vnf1", "--", "agentctl", "config", "update", "--replace", "/vnf1-config.yml")
	kubectl(s.T(), s.kubectx, "exec", "-i", "vpp-vnf2", "--", "agentctl", "config", "update", "--replace", "/vnf2-config.yml")
	kubectl(s.T(), s.kubectx, "exec", "-i", "vpp-vswitch", "--", "agentctl", "config", "update", "--replace", "/vswitch-config.yml")
}

func (s *BasicTestSuite) TestDiscover() {
	t := s.T()

	p, err := kube.NewProvider("", s.kubectx)
	if err != nil {
		t.Fatal(err)
	}

	c := client.NewClient()
	if err := c.AddProvider(p); err != nil {
		t.Fatal(err)
	}

	handlers, err := p.Query(map[string]string{"label": "app=vpp"})
	s.NoError(err)
	s.Equal(3, len(handlers))

	for _, h := range handlers {
		t.Logf("- %v: %+v", h.ID(), h.Metadata())
		instance, err := vpp.NewInstance(h)
		s.NoError(err)
		t.Logf("instance: %+v", instance)
	}
}

func (s *BasicTestSuite) TestTracer() {
	var opts cmd.ProviderFlags
	opts.Kube.Context = s.kubectx
	opts.Queries = []string{"label=app=vpp"}
	cli := cmd.NewProbeCli()
	err := cli.Initialize(opts)
	s.NoError(err)

	tracerOpts := cmd.DefaultTracerOptions
	tracerOpts.CustomCmd = fmt.Sprintf("kubectl --context=%s exec -i vpp-vswitch -- ping -c 1 192.168.23.2", s.kubectx)
	err = cmd.RunTracer(cli, tracerOpts)
	s.NoError(err)
}
