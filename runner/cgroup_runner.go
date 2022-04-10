package runner

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/bboozzoo/piled/cgroup"
)

type cgroupRunner struct {
	cgRoot      string
	storageRoot string
}

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
	storageRoot := filepath.Join(os.TempDir(), "piled")
	return &cgroupRunner{
		cgRoot:      cgCurrent,
		storageRoot: storageRoot,
	}, nil
}

func (r *cgroupRunner) StartJob(name string, config Config) error {
	cg := filepath.Join(r.cgRoot, name)
	if err := cgroup.Add(cg); err != nil {
		return fmt.Errorf("cannot add job cgroup %v: %v", cg, err)
	}
	if config.IOMax != "" {
		if err := cgroup.WriteProperty(cg, "io.max", config.IOMax); err != nil {
			return fmt.Errorf("cannot set IO max: %v", err)
		}
	}
	if config.CPUMax != "" {
		if err := cgroup.WriteProperty(cg, "cpu.max", config.CPUMax); err != nil {
			return fmt.Errorf("cannot set CPU pressure: %v", err)
		}
	}
	if config.MemoryMax != "" {
		if err := cgroup.WriteProperty(cg, "memory.max", config.MemoryMax); err != nil {
			return fmt.Errorf("cannot set CPU pressure: %v", err)
		}
		if err := cgroup.WriteProperty(cg, "memory.oom.group", "1"); err != nil {
			return fmt.Errorf("cannot enable OOM group kill: %v", err)
		}
	}
	storageDir := filepath.Join(r.storageRoot, name)
	if err := os.MkdirAll(storageDir, 0700); err != nil {
		return fmt.Errorf("cannot prepare storage directory: %v", err)
	}

	outputFile, err := os.Create(filepath.Join(storageDir, "output"))
	if err != nil {
		return fmt.Errorf("cannot open storage file: %v", err)
	}
	cmd := exec.Command("/proc/self/exe", config.Command...)
	cmd.Stdin = nil
	cmd.Stdout = outputFile
	cmd.Stderr = outputFile
	cmd.Env = os.Environ()
	shimEnv := []string{
		"_SHIM_IN_NAMESPACE=1",
		"_SHIM_CG=" + cg,
	}
	cmd.Env = append(cmd.Env, shimEnv...)
	cmd.SysProcAttr = &unix.SysProcAttr{
		Cloneflags: unix.CLONE_NEWPID | // PID
			unix.CLONE_NEWNET | // network
			unix.CLONE_NEWNS, // mount
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("cannot start job: %v", err)
	}
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

// IsShimEntry returns true if the process is executing as a runner shim
// entrypoint.
func IsShimEntry() bool {
	return os.Getenv("_SHIM_IN_NAMESPACE") == "1"
}

// ShimEntry is an entrypoint for the intermediate step of running the desired
// process. It is expected that this call does not return, unless there was an
// error setting up the environment.
func ShimEntry() error {
	if os.Getenv("_SHIM_IN_NAMESPACE") != "1" {
		return fmt.Errorf("cannot use entrypoint when not in namespace")
	}
	cg := os.Getenv("_SHIM_CG")
	if cg == "" {
		return fmt.Errorf("cannot run without cgroup path")
	}

	if err := prepareMountNS(); err != nil {
		return fmt.Errorf("cannot prepare mount ns: %v", err)
	}
	// we're expecting the cgroup to have been created already
	if err := cgroup.MovePidTo(os.Getpid(), cg); err != nil {
		return fmt.Errorf("cannot move to cgroup %v: %v", cg, err)
	}

	argv0 := os.Args[1]
	argv := os.Args[1:]
	logrus.Tracef("command: %q", argv)
	if err := unix.Exec(argv0, argv, nil); err != nil {
		return fmt.Errorf("exec failed: %v", err)
	}
	return nil
}

func prepareMountNS() error {
	// fix mount propagation, rprivate, such that we change change the
	// filesystem all we want
	if err := unix.Mount("/", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("cannot change mount propagation to rprivate: %v", err)
	}
	// fixup /proc, by first unmounting the current view of processes
	if err := unix.Unmount("/proc", unix.MNT_DETACH); err != nil {
		return fmt.Errorf("cannot umount /proc: %v", err)
	}
	// and mount a new one that matches our namespace
	if err := unix.Mount("proc", "/proc", "proc", 0, ""); err != nil {
		return fmt.Errorf("cannot mount /proc: %v", err)
	}
	return nil
}
