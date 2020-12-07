package probe

import "fmt"

// Env defines an environment for probe provider.
type Env string

type Probe struct {
	Provider string
	Location string

	Handler
}

func (i *Probe) String() string {
	return fmt.Sprintf("%s", i.ID())
}

// ID returns a string that identifies the instance.
func (i *Probe) ID() string {
	return i.Location
}
