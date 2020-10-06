package probe

var DefaultProvider = new(LocalProvider)

// InstanceProvider is a common interface for finding instances.
type Provider interface {
	Discover(query ...interface{}) ([]Handler, error)
}

// LocalProvider finds instances running on the host.
type LocalProvider struct{}

func (l *LocalProvider) Discover(query ...interface{}) ([]Handler, error) {
	instance := &LocalHandler{}
	return []Handler{instance}, nil
}
