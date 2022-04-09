package runner

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/bboozzoo/piled/cgroup"
)

type cgroupRunner struct{}

func NewCgroupRunner() (*cgroupRunner, error) {
	cgCurrent, err := cgroup.Current()
	if err != nil {
		return nil, fmt.Errorf("cannot read current cgroup: %v", err)
	}
	cgRunner := filepath.Join(cgCurrent, "runner")
	if err := cgroup.Add(cgRunner); err != nil {
		return nil, fmt.Errorf("cannot add cgroup %v: %v", cgRunner, err)
	}
	if err := cgroup.MovePidTo(os.Getpid(), cgRunner); err != nil {
		return nil, fmt.Errorf("cannot move current process to cgroup %v: %v",
			cgRunner, err)
	}
	// enable controllers
	if err := cgroup.WriteProperty(cgCurrent, "cgroup.subtree_control", "+cpu +io +memory"); err != nil {
		return nil, fmt.Errorf("cannot enable controllers in %v: %v", cgCurrent, err)
	}
	return &cgroupRunner{}, nil
}

func (r *cgroupRunner) StartJob(name string, config Config) error {
	return nil
}

func (r *cgroupRunner) StopJob(name string) error {
	return nil
}

func (r *cgroupRunner) Reset(name string) error {
	return nil
}

func (r *cgroupRunner) JobStatus(name string) (*Status, error) {
	return nil, nil
}

func (r *cgroupRunner) JobOutput(name string) (output chan []byte, cancel func(), err error) {
	return nil, nil, nil
}
