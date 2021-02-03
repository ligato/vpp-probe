package vpp

import (
	"encoding/json"
	"fmt"
)

type State int

func (s State) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

func (s *State) UnmarshalJSON(data []byte) error {
	var state string
	err := json.Unmarshal(data, &state)
	if err != nil {
		return err
	}
	switch state {
	case State(StateOK).String():
		*s = StateOK
	case State(StateChecking).String():
		*s = StateChecking
	case State(StateOK).String():
		*s = StateOK
	case State(StateError).String():
		*s = StateError
	default:
		return fmt.Errorf("invalid state: %q", state)
	}
	return nil
}

const (
	StateUnknown = iota
	StateChecking
	StateOK
	StateError
)

func (s State) String() string {
	switch s {
	case StateOK:
		return "OK"
	case StateChecking:
		return "checking"
	case StateError:
		return "error"
	case StateUnknown:
		return "unknown"
	default:
		return fmt.Sprintf("%#v", s)
	}
}

type Status struct {
	State State
	Err   error
}

func (s Status) String() string {
	if s.Err != nil {
		return fmt.Sprintf("%v (error: %v)", s.State, s.Err)
	}
	return fmt.Sprintf("%v", s.State)
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
