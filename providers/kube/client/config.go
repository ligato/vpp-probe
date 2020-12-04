package client

import (
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

func AllContextsConfigs(kubeconfig string) []*Config {
	config := NewConfig(kubeconfig)
	config.KubeConfig = kubeconfig
	var configs []*Config
	for _, ctx := range config.Contexts() {
		cfg := NewConfig(kubeconfig)
		cfg.Context = ctx
		configs = append(configs, cfg)
	}
	return configs
}

type Config struct {
	KubeConfig string
	Context    string

	rawConfig    *clientcmdapi.Config
	clientConfig clientcmd.ClientConfig
}

func NewConfig(kubeConfig string) *Config {
	return &Config{
		KubeConfig: kubeConfig,
	}
}

func (c *Config) Contexts() []string {
	raw := c.rawConfig
	if raw == nil {
		var err error
		raw, err = c.toConfigLoader().ConfigAccess().GetStartingConfig()
		if err != nil {
			return nil
		}
	}
	var contexts []string
	for c := range raw.Contexts {
		contexts = append(contexts, c)
	}
	return contexts
}

func (c *Config) CurrentContext() string {
	currentContext := c.rawConfig.CurrentContext
	if c.Context != "" {
		currentContext = c.Context
	}
	_, ok := c.rawConfig.Contexts[currentContext]
	if !ok {
		return ""
	}
	return currentContext
}

func (c *Config) GetContext() *clientcmdapi.Context {
	currentContext := c.rawConfig.CurrentContext
	if c.Context != "" {
		currentContext = c.Context
	}
	ctx, ok := c.rawConfig.Contexts[currentContext]
	if !ok {
		return nil
	}
	return ctx
}

func (c *Config) ClientConfig() (clientcmd.ClientConfig, error) {
	c.clientConfig = c.toConfigLoader()
	raw, err := c.clientConfig.RawConfig()
	if err != nil {
		return nil, err
	}
	c.rawConfig = &raw
	return c.clientConfig, nil
}

func (c *Config) toConfigLoader() clientcmd.ClientConfig {
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	loadingRules.DefaultClientConfig = &clientcmd.DefaultClientConfig
	if c.KubeConfig != "" {
		loadingRules.ExplicitPath = c.KubeConfig
	}

	overrides := &clientcmd.ConfigOverrides{
		ClusterDefaults: clientcmd.ClusterDefaults,
	}
	if c.Context != "" {
		overrides.CurrentContext = c.Context
	}

	return clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		loadingRules,
		overrides,
	)
}
