package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/jessevdk/go-flags"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/bboozzoo/piled/utils"
)

type options struct {
	CgRoot      string `long:"cg-root"`
	Name        string `long:"name"`
	InNamespace bool   `long:"in-namespace" hidden:"yes"`
	Positional  struct {
		Command []string `positional-arg-name:"command" required:"1"`
	} `positional-args:"yes"`
}

func moveToCgroup(path string) error {
	return nil
}

func run(opts *options) error {
	if err := os.MkdirAll(filepath.Join(opts.CgRoot, opts.Name), 0755); err != nil {
		return fmt.Errorf("cannot create cgroup dir: %v", err)
	}

	// TODO: what if this goes over argv length?
	args := []string{
		"--in-namespace",
		"--cg-root", opts.CgRoot,
		"--name", opts.Name,
		"--",
	}
	args = append(args, opts.Positional.Command...)
	logrus.Tracef("running: %v", args)
	cmd := exec.Command("/proc/self/exe", args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()
	cmd.SysProcAttr = &unix.SysProcAttr{
		Cloneflags: unix.CLONE_NEWPID |
			unix.CLONE_NEWNET |
			unix.CLONE_NEWCGROUP,
	}
	return cmd.Run()
}

func runInNamespace(opts *options) error {
	logrus.Tracef("in namespace")
	// this ought to print 1
	logrus.Tracef("pid: %v", os.Getpid())
	// // TODO setup cgroup
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
		err = run(&opts)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
