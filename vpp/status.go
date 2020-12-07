package vpp

import "fmt"

type State int

const (
	StateUnknown = iota
	StateChecking
	StateOK
	StateError
)

type Status struct {
	State State
	Err   error
}

func (s Status) String() string {
	switch s.State {
	case StateOK:
		return "OK"
	case StateChecking:
		return "checking"
	case StateError:
		return "error"
	case StateUnknown:
		return "unknown"
	default:
		return fmt.Sprint(s.State)
	}
}

func (s *Status) SetError(err error) {
	s.State = StateError
	s.Err = err
}

type APIStatus struct {
	CLI      Status
	BinAPI   Status
	StatsAPI Status
	LastErr  error
}

func (s APIStatus) String() string {
	str := fmt.Sprintf("cli: %v / api: %v / stats: %v", s.CLI, s.BinAPI, s.StatsAPI)
	if s.LastErr != nil {
		str += fmt.Sprintf(" (last err: %v)", s.LastErr)
	}
	return str
}
