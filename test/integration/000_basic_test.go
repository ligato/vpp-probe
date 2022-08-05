package integration

import (
	"strings"

	"go.ligato.io/vpp-probe/cmd"
	"go.ligato.io/vpp-probe/providers"
)

func (s *DockerSuite) TestMultiCommandCli() {
	cli, err := cmd.NewProbeCli()
	s.Require().NoError(err)

	var opts cmd.ProbeOptions
	opts.Env = providers.Docker
	opts.Queries = []string{"name=" + s.vpp1}

	cmd.InitOptions(cli, cmd.GlobalOptions{
		Debug:    true,
		LogLevel: "trace",
		Color:    "on",
	})

	err = cli.Initialize(opts)
	s.Require().NoError(err)

	err = cli.Client().DiscoverInstances(cli.Queries()...)
	s.Require().NoError(err)

	instances := cli.Client().Instances()
	if s.Len(instances, 1, "Expected single instance") {
		instance := instances[0]

		cmds := []string{
			"show version",
			"show int",
		}
		c := strings.Join(cmds, "\n")
		out, err := instance.RunCli(c)
		s.NoError(err, "RunCli should succeed")
		s.Contains(out, "local0")
	}
}
