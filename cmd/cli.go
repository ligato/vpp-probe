package cmd

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/sirupsen/logrus"

	"go.ligato.io/vpp-probe/client"
	"go.ligato.io/vpp-probe/probe"
	"go.ligato.io/vpp-probe/providers"
	"go.ligato.io/vpp-probe/providers/docker"
	"go.ligato.io/vpp-probe/providers/kube"
	"go.ligato.io/vpp-probe/providers/local"
)

type Cli interface {
	Controller() *client.Controller
	Queries() []map[string]string
	Out() io.Writer
	Err() io.Writer
	In() io.ReadCloser
}

type ProbeCli struct {
	ctl     *client.Controller
	queries []map[string]string

	in  io.ReadCloser
	out io.Writer
	err io.Writer
}

func NewProbeCli() *ProbeCli {
	opts := &ProbeCli{
		in:  os.Stdin,
		out: os.Stdout,
		err: os.Stderr,
	}
	return opts
}

func (cli *ProbeCli) Controller() *client.Controller {
	return cli.ctl
}

func (cli *ProbeCli) Queries() []map[string]string {
	return cli.queries
}

func (cli *ProbeCli) Out() io.Writer {
	return cli.out
}

func (cli *ProbeCli) Err() io.Writer {
	return cli.err
}

func (cli *ProbeCli) In() io.ReadCloser {
	return cli.in
}

func (cli *ProbeCli) Initialize(opts ProviderFlags) (err error) {
	cli.ctl, err = setupController(opts)
	if err != nil {
		return fmt.Errorf("controller setup error: %w", err)
	}

	cli.queries = parseQueries(opts.Queries)

	return nil
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

func setupController(opts ProviderFlags) (*client.Controller, error) {
	env := resolveEnv(opts)

	logrus.Debugf("provider env: %v", env)

	probectl := client.NewController()

	pvds, err := setupProviders(env, opts)
	if err != nil {
		return nil, err
	}

	logrus.Debugf("adding %v providers", len(pvds))

	for _, provider := range pvds {
		if err := probectl.AddProvider(provider); err != nil {
			logrus.Warnf("add provider failed: %v", err)
			continue
		}
		logrus.Debugf("%v provider %v connected", provider.Env(), provider.Name())
	}

	return probectl, nil
}

func setupProviders(env providers.Env, opt ProviderFlags) ([]probe.Provider, error) {
	switch env {
	case providers.Local:
		prov, err := setupLocalEnv(opt)
		if err != nil {
			return nil, err
		}
		return []probe.Provider{prov}, nil
	case providers.Kube:
		provs, err := setupKubeEnv(opt.Kube.Kubeconfig, opt.Kube.Context)
		if err != nil {
			return nil, err
		}
		return provs, nil
	case providers.Docker:
		return setupDockerEnv(opt)
	default:
		return nil, fmt.Errorf("invalid env: %q", env)
	}
}

func resolveEnv(opts ProviderFlags) (env providers.Env) {
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

func setupDockerEnv(opt ProviderFlags) ([]probe.Provider, error) {
	provider, err := docker.NewProvider(opt.Docker.Host)
	if err != nil {
		return nil, err
	}
	return []probe.Provider{provider}, nil
}

func setupLocalEnv(opt ProviderFlags) (probe.Provider, error) {
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

	provider, err := local.NewProvider(cfg)
	if err != nil {
		return nil, err
	}

	return provider, nil
}

func setupKubeEnv(kubeconfig, context string) ([]probe.Provider, error) {
	var pvds []probe.Provider

	isSeparator := func(c rune) bool {
		switch c {
		case ',', ';', ':', ' ':
			return true
		}
		return false
	}
	contexts := strings.FieldsFunc(context, isSeparator)
	for _, ctx := range contexts {
		provider, err := kube.NewProvider(kubeconfig, ctx)
		if err != nil {
			return nil, err
		}
		pvds = append(pvds, provider)
	}

	return pvds, nil
}
