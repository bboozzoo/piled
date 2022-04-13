package runner

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/bboozzoo/piled/cgroup"
)

type jobState struct {
	cg         string
	outputFile string
	cmd        *exec.Cmd
	exitStatus int
	termSignal int
	oomKill    bool
	active     bool
	done       chan struct{}

	lock sync.Mutex
}

// CgroupRunner is a runner that uses cgroups to organize the jobs.
type CgroupRunner struct {
	cgRoot      string
	storageRoot string
	jobs        map[string]*jobState
	jobsLock    sync.Mutex
}

var cgroupIsV2 = cgroup.IsV2

// NewCgroupRunner returns a new runner, or an error. Note that creating a
// runner means that the current process is moved to a new shim cgroup called
// 'runner'. The IO, CPU and memory controllers get enabled for subtree
// hierarchy. The config is optional.
func NewCgroupRunner(config *RunnerConfig) (*CgroupRunner, error) {
	v2, err := cgroupIsV2()
	if err != nil {
		return nil, fmt.Errorf("cannot query cgroup version: %v", err)
	}
	if !v2 {
		return nil, fmt.Errorf("unsupported cgroup version: %v", err)
	}

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
	storageRoot := filepath.Join(os.TempDir(), "cgroup-runner-output")
	if config != nil && config.StorageRoot != "" {
		storageRoot = config.StorageRoot
	}
	return &CgroupRunner{
		cgRoot:      cgCurrent,
		storageRoot: storageRoot,
		jobs:        make(map[string]*jobState),
	}, nil
}

var procSelfExe = "/proc/self/exe"

// jobFindAndLock find a job matching the given name, return it taking it's
// lock.
func (r *CgroupRunner) jobFindAndLock(name string) (*jobState, error) {
	r.jobsLock.Lock()
	defer r.jobsLock.Unlock()
	js, ok := r.jobs[name]
	if !ok {
		return nil, JobNotFoundError
	}

	// job exists, lock and return
	js.lock.Lock()
	return js, nil
}

var cmdStart = func(cmd *exec.Cmd) error {
	return cmd.Start()
}

// Start a new job with a given name.
//
// This will spawn a new process by calling /proc/self/exe with a number of
// command line arguments. The child is run with a new PID, memory and network
// namespace. The child's stderr and stdout will be redirected to a file, while
// stdin is closed. The actual job's command is launched through a shim which
// moves the child to a new cgroup under the current hierarchy and execs the
// command. The caller must provide means for reaching the shim's entrypoint,
// preferrably testing with IsShimEntry() and calling ShimEntry() if the test is
// positive.
func (r *CgroupRunner) Start(name string, config Config) error {
	// TODO check if job with given name already exists

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
	if err := os.MkdirAll(r.storageRoot, 0700); err != nil {
		return fmt.Errorf("cannot prepare storage directory: %v", err)
	}
	outputPath := filepath.Join(r.storageRoot, name)
	outputFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("cannot open storage file: %v", err)
	}
	cmd := exec.Command(procSelfExe, config.Command...)
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
	if err := cmdStart(cmd); err != nil {
		outputFile.Close()
		return fmt.Errorf("cannot start job: %v", err)
	}
	// the fd is no longer needed
	outputFile.Close()

	r.jobsLock.Lock()
	defer r.jobsLock.Unlock()
	js := &jobState{
		cg:         cg,
		outputFile: outputPath,
		cmd:        cmd,
		active:     true,
		done:       make(chan struct{}),
	}
	r.jobs[name] = js
	logrus.Tracef("jobs: %v", r.jobs)

	go r.jobWaitUntilDoneUnlocked(js)

	return nil
}

// Stop stops a job with a given name, returns the job's status or an error.
// All resources associated with a job are released, its output file is removed,
// thus if the output is of value, it should be collected earlier. If the job's
// process has not completed yet, it will be forcefully killed.
func (r *CgroupRunner) Stop(name string) (*Status, error) {
	js, err := r.jobFindAndLock(name)
	if err != nil {
		return nil, err
	}
	defer js.lock.Unlock()

	if js.active {
		logrus.Tracef("job still active, killing")
		if err := cgroup.WriteProperty(js.cg, "cgroup.kill", "1"); err != nil {
			return nil, fmt.Errorf("cannot request all processes to be killed: %v", err)
		}
	}

	// unlock so that the process handling can update the job's state
	js.lock.Unlock()
	// wait for the job to complete
	<-js.done
	// and grab the lock again, an unlock was already scheduled to run on
	// return
	js.lock.Lock()

	if err := cgroup.Remove(js.cg); err != nil {
		return nil, fmt.Errorf("cannot remove group: %v", err)
	}
	if err := os.Remove(js.outputFile); err != nil {
		// non fatal, tough luck
		logrus.Tracef("cannot remove output file: %v", err)
	}
	status := &Status{
		Active:     js.active, // which should be false
		ExitStatus: js.exitStatus,
		Signal:     js.termSignal,
		OOM:        js.oomKill,
	}
	// drop the job
	r.jobsLock.Lock()
	defer r.jobsLock.Unlock()
	delete(r.jobs, name)

	return status, nil
}

func (r *CgroupRunner) jobWaitUntilDoneUnlocked(js *jobState) {
	err := js.cmd.Wait()
	logrus.Tracef("wait err: %v", err)

	js.lock.Lock()
	defer js.lock.Unlock()

	if err != nil {
		pErr, ok := (err).(*exec.ExitError)
		if !ok {
			logrus.Tracef("cannot wait for process: %v", err)
			return
		}
		if sws, ok := pErr.Sys().(syscall.WaitStatus); ok {
			ws := unix.WaitStatus(sws)
			logrus.Tracef("job failed, signal? %v (%v)", ws.Signaled(), ws.Signal())
			js.exitStatus = ws.ExitStatus()
			if ws.Signaled() {
				if ws.Signal() == os.Kill {
					// maybe OOM
					gk, err := cgroup.ReadKVProperty(js.cg, "memory.events.local", "oom_group_kill")
					if err != nil {
						logrus.Tracef("cannot process memory.events.local: %v", err)
					} else if gk == "1" {
						logrus.Tracef("OOM kill")
						js.oomKill = true
					}
				}
				js.termSignal = int(ws.Signal())
			}
		}
	} else {
		logrus.Tracef("job succeeded")
		js.exitStatus = 0
	}
	js.active = false
	// cmd is not neded anymore
	js.cmd = nil

	// the main process, which had pid 1 in the namespace, has stopped, kernel
	// took care of killing all the remaining processes

	// let everyone know that the job is done
	close(js.done)
}

// Status of a job. If the job has already completed, its status will indicate
// that the active status is false.
func (r *CgroupRunner) Status(name string) (*Status, error) {
	js, err := r.jobFindAndLock(name)
	if err != nil {
		return nil, err
	}
	defer js.lock.Unlock()

	return &Status{
		Active:     js.active,
		ExitStatus: js.exitStatus,
		Signal:     js.termSignal,
		OOM:        js.oomKill,
	}, nil
}

// Output streams the job's output on channel output, which can be canceled
// by calling the provided cancel function. The output channel will
// automatically close when the job completes and becomes inactive. If the job
// is already inactive, all of its output will be received in chunks over the
// output channel, after which the channel will be closed too.
//
// TODO use a smarter output channel to convey a struct with either output bytes
// or an error
func (r *CgroupRunner) Output(name string) (output <-chan []byte, cancel func(), err error) {
	js, err := r.jobFindAndLock(name)
	if err != nil {
		return nil, nil, err
	}
	// this is ok, as further code will only reference the done channel and
	// keeps an open file
	defer js.lock.Unlock()

	logrus.Tracef("output file: %v", js.outputFile)
	f, err := os.Open(js.outputFile)
	if err != nil {
		return nil, nil, err
	}
	// no need to defer a close, there are no error points between here and
	// the goroutine that feeds the output

	chunksChan := make(chan []byte)
	// for cancelling
	cancelChan := make(chan struct{})

	sendBytes := func(howMuch int64) error {
		logrus.Tracef("send %v bytes", howMuch)
		for sent := int64(0); sent < howMuch; {
			buf := make([]byte, 4096)
			end := howMuch - sent
			if end > int64(len(buf)) {
				end = int64(len(buf))
			}
			n, err := f.Read(buf[:end])
			if err != nil {
				return fmt.Errorf("cannot read: %v", err)
			}
			logrus.Tracef("read: %v", n)
			chunksChan <- buf[:end]
			sent += int64(n)
		}
		return nil
	}
	go func() {
		logrus.Tracef("output feeder")
		// TODO: use inotify rather than poor man's poll

		// actual close of a file opened in the parent
		defer f.Close()
		defer close(chunksChan)
		tick := time.NewTicker(time.Second)
		defer tick.Stop()

		oldSize := int64(0)
		needLastCheck := true
	Loop:
		for {
			fi, err := f.Stat()
			if err != nil {
				logrus.Tracef("cannot stat: %v", err)
				return
			}
			nowSize := fi.Size()
			logrus.Tracef("now size: %v", nowSize)
			if nowSize < oldSize {
				logrus.Tracef("output truncated")
				return
			}
			if nowSize > oldSize {
				if err := sendBytes(nowSize - oldSize); err != nil {
					logrus.Tracef("cannot send: %v", err)
					return
				}
				oldSize = nowSize
			}
			select {
			case <-cancelChan:
				logrus.Tracef("output canceled")
				break Loop
			case <-js.done:
				if needLastCheck {
					// do one last check before closing the
					// output
					needLastCheck = false
					continue
				}
				// job has finished, no more output
				return
			case <-tick.C:
				logrus.Tracef("send tick")
			}
		}
	}()
	return chunksChan, func() { close(cancelChan) }, nil
}

// IsShimEntry returns true if the process is executing as a runner shim
// entrypoint.
func IsShimEntry() bool {
	return os.Getenv("_SHIM_IN_NAMESPACE") == "1"
}

var (
	unixExec    = unix.Exec
	unixMount   = unix.Mount
	unixUnmount = unix.Unmount
)

// ShimEntry is an entrypoint for the intermediate step of running the desired
// process. It is expected that this call does not return, unless there was an
// error setting up the environment.
func ShimEntry() error {
	if os.Getenv("_SHIM_IN_NAMESPACE") != "1" {
		return errors.New("cannot use entrypoint when not in namespace")
	}
	cg := os.Getenv("_SHIM_CG")
	if cg == "" {
		return errors.New("cannot run without cgroup path")
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
	if err := unixExec(argv0, argv, nil); err != nil {
		return fmt.Errorf("exec failed: %v", err)
	}
	return nil
}

func prepareMountNS() error {
	// fix mount propagation, rprivate, such that we change change the
	// filesystem all we want
	if err := unixMount("/", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("cannot change mount propagation to rprivate: %v", err)
	}
	// fixup /proc, by first unmounting the current view of processes
	if err := unixUnmount("/proc", unix.MNT_DETACH); err != nil {
		return fmt.Errorf("cannot umount /proc: %v", err)
	}
	// and mount a new one that matches our namespace
	if err := unixMount("proc", "/proc", "proc", 0, ""); err != nil {
		return fmt.Errorf("cannot mount /proc: %v", err)
	}
	return nil
}
