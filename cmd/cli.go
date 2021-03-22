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

func initClient(opts ProbeOptions) (*client.Client, error) {
	env := resolveEnv(opts)

	logrus.Debugf("resolved env: %v", env)

	probeClient, err := client.NewClient()
	if err != nil {
		return nil, err
	}

	provs, err := setupProviders(env, opts)
	if err != nil {
		return nil, err
	}

	logrus.Debugf("adding %v providers", len(provs))

	for _, provider := range provs {
		if err := probeClient.AddProvider(provider); err != nil {
			logrus.Warnf("adding provider failed: %v", err)
			continue
		}
		logrus.Debugf("%v provider %q ready", provider.Env(), provider.Name())
	}

	return probeClient, nil
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

func setupProviders(env providers.Env, opt ProbeOptions) ([]providers.Provider, error) {
	switch env {
	case providers.Local:
		prov, err := setupLocalEnv(opt)
		if err != nil {
			return nil, err
		}
		return []providers.Provider{prov}, nil
	case providers.Kube:
		return setupKubeEnv(opt)
	case providers.Docker:
		return setupDockerEnv(opt)
	default:
		return nil, fmt.Errorf("unknown env: %q", env)
	}
}

func setupLocalEnv(opt ProbeOptions) (providers.Provider, error) {
	cfg := local.DefaultConfig()

	if opt.APISocket != "" {
		cfg.BinapiAddr = opt.APISocket
	}
	if opt.StatsSocket != "" {
		cfg.StatsAddr = opt.StatsSocket
	}
	if opt.CLISocket != "" {
		cfg.CliAddr = opt.CLISocket
	}

	return local.NewProvider(cfg), nil
}

// TODO: add unit test for different combinations of kubeconfigs/contexts
func setupKubeEnv(opt ProbeOptions) ([]providers.Provider, error) {
	// split by comma
	kubeconfigs := strings.Split(opt.Kube.Kubeconfig, ",")
	contexts := strings.Split(opt.Kube.Context, ",")

	if len(kubeconfigs) > 1 && (len(contexts) > 1 || contexts[0] != "") {
		return nil, fmt.Errorf("selecting context(s) is not supported with multiple kubeconfigs")
	}

	var provs []providers.Provider

	if len(kubeconfigs) > 0 && kubeconfigs[0] != "" {
		for _, kubeconfig := range kubeconfigs {
			provider, err := kube.NewProvider(kubeconfig, "")
			if err != nil {
				return nil, err
			}
			provs = append(provs, provider)
		}
	} else {
		kubeconfig := kubeconfigs[0]
		for _, ctx := range contexts {
			provider, err := kube.NewProvider(kubeconfig, ctx)
			if err != nil {
				return nil, err
			}
			provs = append(provs, provider)
		}
	}

	return provs, nil
}

func setupDockerEnv(opt ProbeOptions) ([]providers.Provider, error) {
	provider, err := docker.NewProvider(opt.Docker.Host)
	if err != nil {
		return nil, err
	}

	return []providers.Provider{provider}, nil
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
