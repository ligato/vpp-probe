package kube

import (
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

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

func (k *Config) Contexts() []string {
	raw := k.rawConfig
	if raw == nil {
		var err error
		raw, err = k.toConfigLoader().ConfigAccess().GetStartingConfig()
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

func (k *Config) GetContext() *clientcmdapi.Context {
	currentContext := k.rawConfig.CurrentContext
	if k.Context != "" {
		currentContext = k.Context
	}
	c, ok := k.rawConfig.Contexts[currentContext]
	if !ok {
		return nil
	}
	return c
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
