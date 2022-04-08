package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"github.com/jessevdk/go-flags"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

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

func moveToCgroup(cg string) error {
	logrus.Tracef("moving to cgroup %v", cg)
	pid := os.Getpid()
	return setCgroupKnob(cg, "cgroup.procs", fmt.Sprintf("%v", pid))
}

func setCgroupKnob(cg, knob, value string) error {
	p := filepath.Join(cg, knob)
	logrus.Tracef("setting %v to: %q", p, value)
	f, err := os.OpenFile(p, os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("cannot open cgroups file: %v", err)
	}
	defer f.Close()
	if _, err := fmt.Fprintf(f, "%v\n", value); err != nil {
		return fmt.Errorf("cannot set cgroup %v to %v: %v", knob, value, err)
	}
	return nil
}

var keyNotFoundError = fmt.Errorf("key not found")

func getCgKVEntry(cg, knob, key string) (string, error) {
	p := filepath.Join(cg, knob)
	logrus.Tracef("find %v value of key  %q", p, key)
	f, err := os.Open(p)
	if err != nil {
		return "", fmt.Errorf("cannot open cgroups file: %v", err)
	}
	defer f.Close()
	inf := bufio.NewScanner(f)
	for inf.Scan() {
		l := inf.Text()
		fields := strings.Fields(l)
		if len(fields) != 2 {
			return "", fmt.Errorf("cannot process line %q", l)
		}
		if fields[0] == key {
			return fields[1], nil
		}
	}
	if err := inf.Err(); err != nil {
		return "", fmt.Errorf("cannot read contents of %v: %v", p, err)
	}
	return "", keyNotFoundError
}

func cgCurrent() (string, error) {
	cgNowRaw, err := ioutil.ReadFile("/proc/self/cgroup")
	if err != nil {
		return "", err
	}
	split := bytes.SplitN(bytes.TrimSpace(cgNowRaw), []byte("::"), 2)
	if len(split) != 2 {
		return "", fmt.Errorf("invalid cgroup content: %v", string(cgNowRaw))
	}
	cgNow := filepath.Join(sysFsCgroup, string(split[1]))
	return cgNow, nil
}

func run(opts *options, osArgs1 []string) error {
	// TODO: what if this goes over argv length?
	args := []string{
		"--in-namespace",
	}

	if opts.CgRoot == "" {
		var err error
		opts.CgRoot, err = cgCurrent()
		if err != nil {
			return fmt.Errorf("cannot read current cg: %v", err)
		}
		args = append(args, "--cg-root", opts.CgRoot)
		logrus.Tracef("new cg root: %v", opts.CgRoot)
	}

	cg := filepath.Join(opts.CgRoot, opts.Name)
	if err := os.MkdirAll(cg, 0755); err != nil {
		return fmt.Errorf("cannot create cgroup dir: %v", err)
	}

	// an invariant of cgroup v2 is that only leaf groups are occupied,
	// work towards having this hierarchy:
	// -- group -- runner (this process)
	//          \- job 1
	//          \- job 2
	//
	// should the 'group' group be occupied, trying to enable subtree
	// controllers will fail with either EBUSY or ENOTSUPP
	cgRunner := filepath.Join(opts.CgRoot, "runner")
	if err := os.MkdirAll(cgRunner, 0755); err != nil {
		return fmt.Errorf("cannot create runner cgroup: %v", err)
	}
	if err := moveToCgroup(cgRunner); err != nil {
		return fmt.Errorf("cannot move to runner cgroup: %v", err)
	}
	cgJob := filepath.Join(opts.CgRoot, opts.Name)

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
			gk, err := getCgKVEntry(cgJob, "memory.events.local", "oom_group_kill")
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

	cgNow, err := cgCurrent()
	if err != nil {
		return fmt.Errorf("cannot read current cg: %v", err)
	}
	logrus.Tracef("current cg: %v", cgNow)

	if err := moveToCgroup(cg); err != nil {
		return fmt.Errorf("cannot move to cgroup %v: %v", cg, err)
	}

	if opts.IO != "" {
		if err := setCgroupKnob(cgRoot, "cgroup.subtree_control", "+io"); err != nil {
			return fmt.Errorf("cannot enable io controller in %v: %v", cgRoot, err)
		}
		if err := setCgroupKnob(cg, "io.max", opts.IO); err != nil {
			return fmt.Errorf("cannot set IO pressure: %v", err)
		}
	}
	if opts.CPU != "" {
		if err := setCgroupKnob(cgRoot, "cgroup.subtree_control", "+cpu"); err != nil {
			return fmt.Errorf("cannot enable io controller in %v: %v", cgRoot, err)
		}
		if err := setCgroupKnob(cg, "cpu.max", opts.CPU); err != nil {
			return fmt.Errorf("cannot set CPU pressure: %v", err)
		}
	}
	if opts.Memory != "" {
		if err := setCgroupKnob(cgRoot, "cgroup.subtree_control", "+memory"); err != nil {
			return fmt.Errorf("cannot enable io controller in %v: %v", cgRoot, err)
		}
		if err := setCgroupKnob(cg, "memory.max", opts.Memory); err != nil {
			return fmt.Errorf("cannot set CPU pressure: %v", err)
		}
		if err := setCgroupKnob(cg, "memory.oom.group", "1"); err != nil {
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
