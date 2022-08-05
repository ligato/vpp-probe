package docker

import (
	"encoding/json"
	"fmt"

	docker "github.com/fsouza/go-dockerclient"
	"github.com/sirupsen/logrus"

	"go.ligato.io/vpp-probe/probe"
	"go.ligato.io/vpp-probe/providers"
)

// Provider finds instances running in Docker containers.
type Provider struct {
	client *docker.Client
	info   *docker.DockerInfo
}

func NewProvider(endpoint string) (*Provider, error) {
	if endpoint == "" {
		c, err := docker.NewClientFromEnv()
		if err != nil {
			return nil, err
		}
		return NewProviderClient(c)
	}
	c, err := docker.NewClient(endpoint)
	if err != nil {
		return nil, err
	}
	return NewProviderClient(c)
}

func NewProviderClient(c *docker.Client) (*Provider, error) {
	if err := c.Ping(); err != nil {
		return nil, err
	}
	info, err := c.Info()
	if err != nil {
		return nil, err
	}
	b, _ := json.MarshalIndent(info, "", "  ")

	logrus.Tracef("docker info: \n%s\n", b)

	provider := &Provider{
		client: c,
		info:   info,
	}
	return provider, nil
}

func (p *Provider) Env() string {
	return providers.Docker
}

func (p *Provider) Name() string {
	endpoint := p.client.Endpoint()
	return fmt.Sprintf("%v@%v", endpoint, p.info.Name)
}

func (p *Provider) Query(params ...map[string]string) ([]probe.Handler, error) {
	queries, err := parseQueryParams(params)
	if err != nil {
		return nil, err
	}
	logrus.Debugf("-> %d queries to run", len(queries))

	// force single empty query by default
	if len(queries) == 0 {
		queries = []ContainerQuery{{}}
	}

	var all []*docker.Container
	for _, q := range queries {
		logrus.Debugf("running query: %+v", q)

		opts := q.ListContainerOptions()
		containers, err := listContainers(p.client, opts)
		if err != nil {
			return nil, fmt.Errorf("query containers error: %w", err)
		}
		if len(containers) == 0 {
			logrus.Warnf("no containers matching options: %+v", opts)
			continue
		}

		all = append(all, containers...)
	}

	logrus.Debugf("found %d containers", len(all))

	var handlers []probe.Handler
	for _, container := range all {
		handlers = append(handlers, NewHandler(p.client, container))
	}

	if len(handlers) == 0 {
		return nil, fmt.Errorf("no instances found")
	}

	return handlers, nil
}

func listContainers(c *docker.Client, listOpts docker.ListContainersOptions) ([]*docker.Container, error) {
	logrus.Debugf("listing containers (options: %+v)", listOpts)

	cnts, err := c.ListContainers(listOpts)
	if err != nil {
		return nil, err
	}
	logrus.Debugf("%d containers listed", len(cnts))

	var containers []*docker.Container
	for _, cnt := range cnts {
		container, err := c.InspectContainerWithOptions(docker.InspectContainerOptions{
			ID: cnt.ID,
		})
		if err != nil {
			logrus.Warnf("inspecting container %v (%v) failed: %v", cnt.ID, cnt.Names, err)
			continue
		}

		logrus.Tracef("inspected container: %+v", container)
		containers = append(containers, container)
	}

	return containers, nil
}

func parseQueryParams(listParams []map[string]string) ([]ContainerQuery, error) {
	var queries []ContainerQuery
	for _, params := range listParams {
		if params == nil {
			return nil, fmt.Errorf("invalid params: %q", params)
		}
		queries = append(queries, newQuery(params))
	}
	return queries, nil
}

type ContainerQuery struct {
	ID    string
	Name  string
	Label string
}

func newQuery(params map[string]string) ContainerQuery {
	name := params["name"]
	if container, ok := params["container"]; ok && container != "" {
		name = container
	}
	return ContainerQuery{
		ID:    params["id"],
		Name:  name,
		Label: params["label"],
	}
}

func (q ContainerQuery) String() string {
	var s string
	if q.ID != "" {
		s = fmt.Sprintf("ID=%q ", q.ID)
	} else if q.Name != "" {
		s = fmt.Sprintf("Name=%q ", q.Name)
	} else if q.Label != "" {
		s += fmt.Sprintf("Label=%q ", q.Label)
	}
	return s
}

func (q ContainerQuery) ListContainerOptions() docker.ListContainersOptions {
	opts := docker.ListContainersOptions{}
	if q.ID != "" {
		opts.Filters = map[string][]string{
			"id": {q.ID},
		}
	} else if q.Name != "" {
		opts.Filters = map[string][]string{
			"name": {q.Name},
		}
	} else if q.Label != "" {
		opts.Filters = map[string][]string{
			"label": {q.Label},
		}
	}
	return opts
}
