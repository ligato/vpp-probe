package cmd

import (
	"fmt"
	"io"
	"strings"

	"github.com/docker/cli/cli/streams"
	"github.com/moby/term"
	"github.com/sirupsen/logrus"

	"go.ligato.io/vpp-probe/client"
	"go.ligato.io/vpp-probe/providers"
	"go.ligato.io/vpp-probe/providers/docker"
	"go.ligato.io/vpp-probe/providers/kube"
	"go.ligato.io/vpp-probe/providers/local"
)

type Cli interface {
	Initialize(opts ProbeOptions) error
	Client() *client.Client
	Queries() []map[string]string

	Out() *streams.Out
	Err() io.Writer
	In() *streams.In
	Apply(...CliOption) error
}

type ProbeCli struct {
	queries []map[string]string
	client  *client.Client

	out *streams.Out
	err io.Writer
	in  *streams.In
}

func NewProbeCli(opt ...CliOption) (*ProbeCli, error) {
	cli := new(ProbeCli)
	if err := cli.Apply(opt...); err != nil {
		return nil, err
	}
	if cli.out == nil || cli.in == nil || cli.err == nil {
		stdin, stdout, stderr := term.StdStreams()
		if cli.in == nil {
			cli.in = streams.NewIn(stdin)
		}
		if cli.out == nil {
			cli.out = streams.NewOut(stdout)
		}
		if cli.err == nil {
			cli.err = stderr
		}
	}
	return cli, nil
}

func (cli *ProbeCli) Initialize(opts ProbeOptions) (err error) {
	cli.client, err = initClient(opts)
	if err != nil {
		return fmt.Errorf("controller setup error: %w", err)
	}

	cli.queries = parseQueries(opts.Queries)

	return nil
}

func (cli *ProbeCli) Apply(opt ...CliOption) error {
	for _, o := range opt {
		if err := o(cli); err != nil {
			return err
		}
	}
	return nil
}

func (cli *ProbeCli) Client() *client.Client {
	return cli.client
}

func (cli *ProbeCli) Queries() []map[string]string {
	return cli.queries
}

func (cli *ProbeCli) Out() *streams.Out {
	return cli.out
}

func (cli *ProbeCli) Err() io.Writer {
	return cli.err
}

func (cli *ProbeCli) In() *streams.In {
	return cli.in
}

func parseQueries(queries []string) []map[string]string {
	const (
		queryParamSeparator  = ";"
		paramKeyValSeparator = "="
	)
	var queryParams []map[string]string
	for _, q := range queries {
		params := strings.Split(q, queryParamSeparator)
		qp := map[string]string{}
		for _, p := range params {
			if i := strings.Index(p, paramKeyValSeparator); i > 0 {
				key := p[:i]
				val := p[i+1:]
				qp[key] = val
			} else {
				qp[p] = ""
			}
		}
		queryParams = append(queryParams, qp)
	}
	return queryParams
}

func initClient(opts ProbeOptions) (*client.Client, error) {
	env := resolveEnv(opts)

	logrus.Debugf("resolved env: %v", env)

	probeClient, err := client.NewClient()
	if err != nil {
		return nil, err
	}

	pvds, err := setupProviders(env, opts)
	if err != nil {
		return nil, err
	}

	logrus.Debugf("adding %v providers", len(pvds))

	for _, provider := range pvds {
		if err := probeClient.AddProvider(provider); err != nil {
			logrus.Warnf("add provider failed: %v", err)
			continue
		}
		logrus.Debugf("%v provider %v connected", provider.Env(), provider.Name())
	}

	return probeClient, nil
}

func setupProviders(env providers.Env, opt ProbeOptions) ([]providers.Provider, error) {
	switch env {
	case providers.Local:
		prov, err := setupLocalEnv(opt)
		if err != nil {
			return nil, err
		}
		return []providers.Provider{prov}, nil
	case providers.Kube:
		provs, err := setupKubeEnv(opt.Kube.Kubeconfig, opt.Kube.Context)
		if err != nil {
			return nil, err
		}
		return provs, nil
	case providers.Docker:
		return setupDockerEnv(opt)
	default:
		return nil, fmt.Errorf("unknown env: %q", env)
	}
}

func resolveEnv(opts ProbeOptions) providers.Env {
	if opts.Env != "" {
		return providers.Env(opts.Env)
	}
	if opts.Docker.Host != "" {
		return providers.Docker
	}
	if opts.Kube.Kubeconfig != "" || opts.Kube.Context != "" {
		return providers.Kube
	}
	return providers.Local
}

func setupDockerEnv(opt ProbeOptions) ([]providers.Provider, error) {
	provider, err := docker.NewProvider(opt.Docker.Host)
	if err != nil {
		return nil, err
	}
	return []providers.Provider{provider}, nil
}

func setupLocalEnv(opt ProbeOptions) (providers.Provider, error) {
	cfg := local.DefaultConfig()
	if opt.Local.APISocket != "" {
		cfg.BinapiAddr = opt.Local.APISocket
	}
	if opt.Local.StatsSocket != "" {
		cfg.StatsAddr = opt.Local.StatsSocket
	}
	if opt.Local.CLISocket != "" {
		cfg.CliAddr = opt.Local.CLISocket
	}
	return local.NewProvider(cfg), nil
}

func setupKubeEnv(kubeconfig, context string) ([]providers.Provider, error) {
	var pvds []providers.Provider

	isSeparator := func(c rune) bool {
		switch c {
		case ',', ';', ':':
			return true
		}
		return false
	}
	contexts := strings.FieldsFunc(context, isSeparator)

	if len(contexts) == 0 {
		contexts = []string{""}
	}

	for _, ctx := range contexts {
		provider, err := kube.NewProvider(kubeconfig, ctx)
		if err != nil {
			return nil, err
		}
		pvds = append(pvds, provider)
	}

	return pvds, nil
}
