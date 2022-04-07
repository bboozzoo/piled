package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"

	"github.com/jessevdk/go-flags"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/bboozzoo/piled/cgroup"
	"github.com/bboozzoo/piled/utils"
)

type options struct {
	CgRoot      string `long:"cg-root"`
	Name        string `long:"name"`
	IO          string `long:"io"`
	CPU         string `long:"cpu"`
	Memory      string `long:"memory"`
	InNamespace bool   `long:"in-namespace" hidden:"yes"`
	Positional  struct {
		Command []string `positional-arg-name:"command" required:"1"`
	} `positional-args:"yes"`
}

const sysFsCgroup = "/sys/fs/cgroup"

func run(opts *options, osArgs1 []string) error {
	// TODO: what if this goes over argv length?
	args := []string{
		"--in-namespace",
	}

	if opts.CgRoot == "" {
		var err error
		opts.CgRoot, err = cgroup.Current()
		if err != nil {
			return fmt.Errorf("cannot read current cg: %v", err)
		}
		args = append(args, "--cg-root", opts.CgRoot)
		logrus.Tracef("new cg root: %v", opts.CgRoot)
	}

	// an invariant of cgroup v2 is that only leaf groups are occupied,
	// work towards having this hierarchy:
	// -- group -- runner (this process)
	//          \- job 1
	//          \- job 2
	//
	// should the 'group' group be occupied, trying to enable subtree
	// controllers will fail with either EBUSY or ENOTSUPP
	cgJob := filepath.Join(opts.CgRoot, opts.Name)
	cgRunner := filepath.Join(opts.CgRoot, "runner")
	if err := cgroup.Add(cgJob); err != nil {
		return fmt.Errorf("cannot create cgroup dir: %v", err)
	}
	if err := cgroup.Add(cgRunner); err != nil {
		return fmt.Errorf("cannot create runner cgroup: %v", err)
	}
	if err := cgroup.MovePidTo(os.Getpid(), cgRunner); err != nil {
		return fmt.Errorf("cannot move to runner cgroup: %v", err)
	}

	args = append(args, osArgs1...)
	logrus.Tracef("running: %q", args)
	cmd := exec.Command("/proc/self/exe", args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()
	cmd.SysProcAttr = &unix.SysProcAttr{
		Cloneflags: unix.CLONE_NEWPID | // PID
			unix.CLONE_NEWNET | // network
			unix.CLONE_NEWNS, // mount
	}
	// XXX mount namespace has to have the even propagation changed to
	// private once inside

	err := cmd.Run()
	if eErr, ok := err.(*exec.ExitError); ok {
		ws := eErr.Sys().(syscall.WaitStatus)
		logrus.Tracef("exit status: %v (%v)", ws, ws.Signal())
		if ws.Signal() == unix.SIGKILL {
			gk, err := cgroup.ReadKVProperty(cgJob, "memory.events.local", "oom_group_kill")
			if err != nil {
				return fmt.Errorf("cannot process memory.events.local: %v", err)
			}
			if gk == "1" {
				logrus.Tracef("OOM killed")
			}
		}
	}
	return err
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

func runInNamespace(opts *options) error {
	logrus.Tracef("-- in namespace")
	cgRoot := opts.CgRoot
	cg := filepath.Join(cgRoot, opts.Name)

	if err := prepareMountNS(); err != nil {
		return fmt.Errorf("cannot prepare mount ns: %v", err)
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// this ought to print 1
	logrus.Tracef("pid: %v", os.Getpid())

	cgNow, err := cgroup.Current()
	if err != nil {
		return fmt.Errorf("cannot read current cg: %v", err)
	}
	logrus.Tracef("current cg: %v", cgNow)

	if err := cgroup.MovePidTo(os.Getpid(), cg); err != nil {
		return fmt.Errorf("cannot move to cgroup %v: %v", cg, err)
	}

	if opts.IO != "" {
		if err := cgroup.WriteProperty(cgRoot, "cgroup.subtree_control", "+io"); err != nil {
			return fmt.Errorf("cannot enable io controller in %v: %v", cgRoot, err)
		}
		if err := cgroup.WriteProperty(cg, "io.max", opts.IO); err != nil {
			return fmt.Errorf("cannot set IO pressure: %v", err)
		}
	}
	if opts.CPU != "" {
		if err := cgroup.WriteProperty(cgRoot, "cgroup.subtree_control", "+cpu"); err != nil {
			return fmt.Errorf("cannot enable io controller in %v: %v", cgRoot, err)
		}
		if err := cgroup.WriteProperty(cg, "cpu.max", opts.CPU); err != nil {
			return fmt.Errorf("cannot set CPU pressure: %v", err)
		}
	}
	if opts.Memory != "" {
		if err := cgroup.WriteProperty(cgRoot, "cgroup.subtree_control", "+memory"); err != nil {
			return fmt.Errorf("cannot enable io controller in %v: %v", cgRoot, err)
		}
		if err := cgroup.WriteProperty(cg, "memory.max", opts.Memory); err != nil {
			return fmt.Errorf("cannot set CPU pressure: %v", err)
		}
		if err := cgroup.WriteProperty(cg, "memory.oom.group", "1"); err != nil {
			return fmt.Errorf("cannot enable OOM group kill: %v", err)
		}
	}

	argv0 := opts.Positional.Command[0]
	argv := opts.Positional.Command
	logrus.Tracef("exec, argv0: %v argv %v", argv0, argv)
	if err := unix.Exec(argv0, argv, nil); err != nil {
		logrus.Errorf("exec failed: %v", err)
		return fmt.Errorf("exec failed: %v", err)
	}
	return nil
}

func main() {
	var opts options
	logrus.SetLevel(logrus.TraceLevel)
	logrus.SetFormatter(&utils.WithPidFormatter{})
	_, err := flags.ParseArgs(&opts, os.Args[1:])
	if err != nil {
		if utils.IsErrHelp(err) {
			os.Exit(0)
		}
		os.Exit(1)
	}
	if opts.InNamespace {
		err = runInNamespace(&opts)
	} else {
		err = run(&opts, os.Args[1:])
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
