package exec

// Wrapper executes commands using a wrapper command.
type Wrapper struct {
	Interface

	cmd  string
	args []string
}

// Wrap wraps existing Interface with a custom command which is used for
// commands executed via returned Wrapper.
func Wrap(e Interface, cmd string, args ...string) *Wrapper {
	return &Wrapper{
		Interface: e,
		cmd:       cmd,
		args:      args,
	}
}

func (w *Wrapper) Command(cmd string, args ...string) Cmd {
	args = append([]string{cmd}, args...)
	return w.Interface.Command(w.cmd, append(w.args, args...)...)
}
