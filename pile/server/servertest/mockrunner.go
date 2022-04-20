package servertest

import (
	"errors"

	"github.com/bboozzoo/piled/runner"
)

type MockRunner struct {
	StartCb  func(config runner.Config) (name string, err error)
	StopCb   func(name string) (*runner.Status, error)
	StatusCb func(name string) (*runner.Status, error)
	OutputCb func(name string) (<-chan []byte, func(), error)
}

var errNotImplemnted = errors.New("mock not implemented")

func (m *MockRunner) Start(config runner.Config) (name string, err error) {
	if m.StartCb != nil {
		return m.StartCb(config)
	}
	return "", errNotImplemnted
}

func (m *MockRunner) Stop(name string) (*runner.Status, error) {
	if m.StopCb != nil {
		return m.StopCb(name)
	}
	return nil, errNotImplemnted
}
func (m *MockRunner) Status(name string) (*runner.Status, error) {
	if m.StatusCb != nil {
		return m.StatusCb(name)
	}
	return nil, errNotImplemnted
}

func (m *MockRunner) Output(name string) (output <-chan []byte, cancel func(), err error) {
	if m.OutputCb != nil {
		return m.OutputCb(name)
	}
	return nil, nil, errNotImplemnted
}
