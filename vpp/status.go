package vpp

import (
	"encoding/json"
	"fmt"
)

type State int

const (
	StateUnknown State = iota
	StateChecking
	StateOK
	StateError
)

func (s State) String() string {
	switch s {
	case StateUnknown:
		return "unknown"
	case StateOK:
		return "OK"
	case StateChecking:
		return "checking"
	case StateError:
		return "error"
	default:
		return fmt.Sprintf("%#v", s)
	}
}

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
	case StateUnknown.String():
		*s = StateUnknown
	case StateOK.String():
		*s = StateOK
	case StateChecking.String():
		*s = StateChecking
	case StateOK.String():
		*s = StateOK
	case StateError.String():
		*s = StateError
	default:
		return fmt.Errorf("invalid state: %q", state)
	}
	return nil
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

func (s Status) MarshalJSON() ([]byte, error) {
	var errStr string
	if s.Err != nil {
		errStr = s.Err.Error()
	}
	x := struct {
		State State
		Error string
	}{
		State: s.State,
		Error: errStr,
	}
	return json.Marshal(x)
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
