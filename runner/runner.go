package runner

import (
	"errors"
)

var JobNotFoundError = errors.New("job not found")

// Config of a job
type Config struct {
	// Command to run
	Command []string
	// CPUMax in the format of cgroupv2 cpu.max
	CPUMax string
	// CPUMax in the format of cgroupv2 io.max
	IOMax string
	// CPUMax in the format of cgroupv2 memory.max
	MemoryMax string
}

// Status of a job
type Status struct {
	// Active is true when the job is still running
	Active bool
	// Exit status is only meaningful when job is no longer active
	ExitStatus int
	// Signal that terminated the job if non 0
	Signal int
	// OOM is true when the job triggered OOM
	OOM bool
}

// RunnerConfig is a configuration for the runner
type RunnerConfig struct {
	// StorageRoot is where the job output will be stored
	StorageRoot string
}
