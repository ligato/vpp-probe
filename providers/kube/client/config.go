package client

import (
	"fmt"

	"k8s.io/cli-runtime/pkg/genericclioptions"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

func NewConfigWith(kubeconfig string, context string) *Config {
	flags := genericclioptions.NewConfigFlags(true)
	if kubeconfig != "" {
		flags.KubeConfig = &kubeconfig
	}
	if context != "" {
		flags.Context = &context
	}
	return NewConfig(flags)
}

type Config struct {
	flags *genericclioptions.ConfigFlags

	rawConfig    *clientcmdapi.Config
	restConfig   *restclient.Config
	clientConfig clientcmd.ClientConfig
}

func NewConfig(flags *genericclioptions.ConfigFlags) *Config {
	return &Config{flags: flags}
}

func (c *Config) CurrentNamespace() (string, error) {
	if c.flags.Namespace != nil && *c.flags.Namespace != "" {
		return *c.flags.Namespace, nil
	}
	cfg, err := c.RawConfig()
	if err != nil {
		return "", err
	}
	ctx, err := c.CurrentContext()
	if err != nil {
		return "", err
	}
	if ctx, ok := cfg.Contexts[ctx]; ok {
		if ctx.Namespace != "" {
			return ctx.Namespace, nil
		}
	}
	return "", fmt.Errorf("current namespace not found")
}

func (c *Config) CurrentContext() (string, error) {
	if c.flags.Context != nil && *c.flags.Context != "" {
		return *c.flags.Context, nil
	}
	cfg, err := c.RawConfig()
	if err != nil {
		return "", err
	}
	return cfg.CurrentContext, nil
}

func (c *Config) CurrentCluster() (string, error) {
	if c.flags.ClusterName != nil && *c.flags.ClusterName != "" {
		return *c.flags.ClusterName, nil
	}
	cfg, err := c.RawConfig()
	if err != nil {
		return "", err
	}
	current := cfg.CurrentContext
	if c.flags.Context != nil && *c.flags.Context != "" {
		current = *c.flags.Context
	}

	if ctx, ok := cfg.Contexts[current]; ok {
		return ctx.Cluster, nil
	}
	return "", fmt.Errorf("current cluster not found")
}

func (c *Config) GetContext(name string) (*clientcmdapi.Context, error) {
	cfg, err := c.RawConfig()
	if err != nil {
		return nil, err
	}
	if ctx, ok := cfg.Contexts[name]; ok {
		return ctx, nil
	}
	return nil, fmt.Errorf("invalid context %s", name)
}

func (c *Config) Contexts() (map[string]*clientcmdapi.Context, error) {
	cfg, err := c.RawConfig()
	if err != nil {
		return nil, err
	}
	return cfg.Contexts, nil
}

func (c *Config) ContextNames() ([]string, error) {
	cfg, err := c.RawConfig()
	if err != nil {
		return nil, err
	}
	cc := make([]string, 0, len(cfg.Contexts))
	for n := range cfg.Contexts {
		cc = append(cc, n)
	}
	return cc, nil
}

func (c *Config) ClusterNames() ([]string, error) {
	cfg, err := c.RawConfig()
	if err != nil {
		return nil, err
	}
	cc := make([]string, 0, len(cfg.Clusters))
	for name := range cfg.Clusters {
		cc = append(cc, name)
	}
	return cc, nil
}

func (c *Config) RawConfig() (clientcmdapi.Config, error) {
	if c.rawConfig == nil {
		c.ensureConfig()
		raw, err := c.clientConfig.RawConfig()
		if err != nil {
			return raw, err
		}
		c.rawConfig = &raw
		if c.flags.Context == nil {
			c.flags.Context = &c.rawConfig.CurrentContext
		}
	}
	return *c.rawConfig, nil
}

func (c *Config) ConfigAccess() (clientcmd.ConfigAccess, error) {
	c.ensureConfig()
	return c.clientConfig.ConfigAccess(), nil
}

func (c *Config) RESTConfig() (*restclient.Config, error) {
	if c.restConfig != nil {
		return c.restConfig, nil
	}
	var err error
	if c.restConfig, err = c.flags.ToRESTConfig(); err != nil {
		return nil, err
	}
	c.restConfig.QPS = 50
	c.restConfig.Burst = 50
	return c.restConfig, nil
}

func (c *Config) ensureConfig() {
	if c.clientConfig != nil {
		return
	}
	c.clientConfig = c.flags.ToRawKubeConfigLoader()
}
