// Package client contains high-level client for managing instances.
package client

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"go.ligato.io/vpp-probe/providers"
	"go.ligato.io/vpp-probe/vpp"
)

// API defines client API interface.
type API interface {
	AddProvider(provider providers.Provider) error
	GetProvider(name string) providers.Provider
	GetProviders() []providers.Provider
	Instances() []*vpp.Instance
	DiscoverInstances(queryParams ...map[string]string) error
	Close() error
}

// Client is a client for managing providers and instances.
type Client struct {
	providers []providers.Provider
	instances []*vpp.Instance
}

// NewClient returns a new client using given options.
func NewClient(opt ...Opt) (*Client, error) {
	c := &Client{}
	for _, o := range opt {
		if err := o(c); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// Close releases used resources.
func (c *Client) Close() error {
	for _, instance := range c.instances {
		handler := instance.Handler()
		if err := handler.Close(); err != nil {
			logrus.Debugf("closing handler %v failed: %v", handler.ID(), err)
		}
	}
	return nil
}

// GetProvider returns provider with name or nil if not found.
func (c *Client) GetProvider(name string) providers.Provider {
	if c == nil {
		return nil
	}
	for _, p := range c.providers {
		if p.Name() == name {
			return p
		}
	}
	return nil
}

// GetProviders returns all providers.
func (c *Client) GetProviders() []providers.Provider {
	return c.providers
}

// Instances returns list of VPP instances.
func (c *Client) Instances() []*vpp.Instance {
	return c.instances
}

// AddProvider adds provider to the client or returns error if the provided
// was already added.
func (c *Client) AddProvider(provider providers.Provider) error {
	if provider == nil {
		panic("provider is nil")
	}

	// check duplicate
	for _, p := range c.providers {
		if p.Name() == provider.Name() {
			return fmt.Errorf("provider '%v' already added", p)
		}
	}

	c.providers = append(c.providers, provider)

	return nil
}

// DiscoverInstances discovers running VPP instances via probe provider and
// updates the list of instances with active instances from discovery.
func (c *Client) DiscoverInstances(queryParams ...map[string]string) error {
	if len(c.providers) == 0 {
		return fmt.Errorf("no providers available")
	}

	type discovery struct {
		provider  providers.Provider
		instances []*vpp.Instance
		err       error
	}
	discoveryChan := make(chan discovery)

	logrus.Debugf("running instance discovery for %d providers", len(c.providers))

	for _, p := range c.providers {
		go func(provider providers.Provider) {
			instances, err := DiscoverInstances(provider, queryParams...)
			if err != nil {
				logrus.Warnf("provider %q discover error: %v", provider.Name(), err)
			}
			discoveryChan <- discovery{
				provider:  provider,
				instances: instances,
				err:       err,
			}
		}(p)
	}

	discoveries := make(map[providers.Provider]discovery)
	for range c.providers {
		d := <-discoveryChan
		discoveries[d.provider] = d
	}

	var instanceList []*vpp.Instance
	for _, p := range c.providers {
		d := discoveries[p]
		if len(d.instances) > 0 {
			instanceList = append(instanceList, d.instances...)
		}
	}

	// sort instances by ID
	sort.Slice(instanceList, func(i, j int) bool { return instanceList[i].ID() < instanceList[j].ID() })

	c.instances = instanceList
	if len(c.instances) == 0 {
		return fmt.Errorf("no instances discovered")
	}

	return nil
}

// DiscoverInstances discovers running VPP instances using provider and
// returns the list of instances or error if provider query fails.
func DiscoverInstances(provider providers.Provider, queryParams ...map[string]string) ([]*vpp.Instance, error) {
	handlers, err := provider.Query(queryParams...)
	if err != nil {
		return nil, err
	}

	var initInstances []*vpp.Instance
	for _, handler := range handlers {
		log := logrus.WithField("instance", handler.ID())

		inst, err := vpp.NewInstance(handler)
		if err != nil {
			log.Debugf("vpp instance init failed: %v", err)
			continue
		}

		initInstances = append(initInstances, inst)
	}

	instch := make(chan *vpp.Instance, len(initInstances))

	if err := RunOnInstances(initInstances, func(instance *vpp.Instance) error {
		err := instance.Init()
		if err == nil {
			instch <- instance
		}
		return err
	}); err != nil {
		return nil, err
	}
	close(instch)

	var instances []*vpp.Instance
	for inst := range instch {
		instances = append(instances, inst)
	}

	return instances, nil
}

const defaultNumWorkers = 10

func RunOnInstances(instances []*vpp.Instance, workFn func(*vpp.Instance) error) error {
	if len(instances) == 0 {
		return fmt.Errorf("at least one instance required")
	}
	numWorkers := defaultNumWorkers
	if numWorkers > len(instances) {
		numWorkers = len(instances)
	}

	start := time.Now()

	// create work channel to send all instances
	workch := make(chan *vpp.Instance)
	go func() {
		for _, inst := range instances {
			workch <- inst
		}
		close(workch)
	}()

	type Result struct {
		Instance *vpp.Instance
		Error    error
		Elapsed  time.Duration
	}
	resultch := make(chan *Result)

	// start workers to run for instances from work channel
	var wg sync.WaitGroup
	wg.Add(numWorkers)
	for i := 0; i < numWorkers; i++ {
		go func() {
			defer wg.Done()
			for instance := range workch {
				t := time.Now()
				logrus.Tracef("processing instance: %v", instance)
				err := workFn(instance)
				resultch <- &Result{
					Instance: instance,
					Error:    err,
					Elapsed:  time.Since(t),
				}
			}
		}()
	}
	// close result channel when all workers are done
	go func() {
		wg.Wait()
		close(resultch)
	}()

	logrus.Debugf("waiting for results from %d instances", len(instances))

	var results []*Result
	// process completed from result channel
	var anyOk bool
	for res := range resultch {
		if res.Error == nil {
			anyOk = true
		}
		results = append(results, res)
	}
	if !anyOk {
		return fmt.Errorf("all instances encountered errors")
	}

	logrus.Debugf("%d instances finished", len(instances))
	var total time.Duration
	for _, res := range results {
		logrus.Debugf("- %+v", res)
		total += res.Elapsed
	}
	logrus.Tracef("elapsed time %v (total time: %v)", time.Since(start).Round(time.Second), total.Round(time.Second))

	return nil
}
