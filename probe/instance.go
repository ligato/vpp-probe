package probe

// Instance defines a single probe instance.
type Instance struct {
	Provider string
	Location string

	Metadata map[string]string

	Handler `json:"-"`
}

/*func (i *Instance) String() string {
	return fmt.Sprintf("%s", i.ID())
}*/

// ID returns a string that identifies the instance.
/*func (i *Instance) ID() string {
	return i.Handler.ID()
}*/
