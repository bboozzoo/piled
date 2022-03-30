package runner_test

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	. "gopkg.in/check.v1"

	"github.com/bboozzoo/piled/cgroup"
	"github.com/bboozzoo/piled/runner"
	"github.com/bboozzoo/piled/testutils"
)

var _ = Suite(&runnerSuite{})

func TestT(t *testing.T) {
	TestingT(t)
}

type runnerSuite struct {
	testutils.BaseTest
	cgroupRoot string
	tmpdir     string
}

func (s *runnerSuite) SetUpTest(c *C) {
	s.BaseTest.SetUpTest(c)
	s.cgroupRoot = c.MkDir()

	restore := runner.MockUnixExec(func(argv0 string, argv []string, envv []string) error {
		c.Fatalf("unixExec not mocked")
		return fmt.Errorf("unexpected call")
	})
	s.AddCleanup(restore)
	restore = cgroup.MockSysFsCgroup(s.cgroupRoot)
	s.AddCleanup(restore)

	s.tmpdir = c.MkDir()
	oldTmp, wasSet := os.LookupEnv("TMPDIR")
	os.Setenv("TMPDIR", s.tmpdir)
	s.AddCleanup(func() {
		if wasSet {
			os.Setenv("TMPDIR", oldTmp)
		} else {
			os.Unsetenv("TMPDIR")
		}
	})
	s.AddCleanup(runner.MockCgroupIsV2(func() (bool, error) {
		return true, nil
	}))
}

func (s *runnerSuite) TestIsShimEntry(c *C) {
	is := runner.IsShimEntry()
	c.Assert(is, Equals, false)

	os.Setenv("_SHIM_IN_NAMESPACE", "1")
	defer os.Unsetenv("_SHIM_IN_NAMESPACE")

	is = runner.IsShimEntry()
	c.Assert(is, Equals, true)
}

func (s *runnerSuite) TestShimEntryHappy(c *C) {
	os.Setenv("_SHIM_IN_NAMESPACE", "1")
	defer os.Unsetenv("_SHIM_IN_NAMESPACE")
	os.Setenv("_SHIM_CG", "/foo/bar/baz")
	defer os.Unsetenv("_SHIM_CG")

	testutils.MockFile(c, filepath.Join(s.cgroupRoot, "/foo/bar/baz/cgroup.procs"), "")

	execCalls := 0
	restore := runner.MockUnixExec(func(argv0 string, argv []string, envv []string) error {
		execCalls++
		return nil
	})
	defer restore()
	var mounts []string
	var umounts []string
	restore = runner.MockUnixMount(func(source string, target string, fstype string, flags uintptr, data string) error {
		mounts = append(mounts, fmt.Sprintf("%v -> %v type:%q", source, target, fstype))
		return nil
	})
	defer restore()
	restore = runner.MockUnixUnmount(func(target string, flags int) error {
		c.Assert(mounts, DeepEquals, []string{
			// / was already remounted
			`/ -> / type:""`,
		})
		umounts = append(umounts, target)
		return nil
	})
	defer restore()

	err := runner.ShimEntry()
	c.Assert(err, IsNil)
	c.Assert(execCalls, Equals, 1)

	c.Assert(execCalls, Equals, 1)
	c.Assert(mounts, DeepEquals, []string{
		// / was already remounted
		`/ -> / type:""`,
		`proc -> /proc type:"proc"`,
	})
	c.Assert(umounts, DeepEquals, []string{
		"/proc",
	})
}

func (s *runnerSuite) TestShimEntryExecFails(c *C) {
	os.Setenv("_SHIM_IN_NAMESPACE", "1")
	defer os.Unsetenv("_SHIM_IN_NAMESPACE")
	os.Setenv("_SHIM_CG", "/foo/bar/baz")
	defer os.Unsetenv("_SHIM_CG")

	testutils.MockFile(c, filepath.Join(s.cgroupRoot, "/foo/bar/baz/cgroup.procs"), "")

	restore := runner.MockUnixExec(func(argv0 string, argv []string, envv []string) error {
		return fmt.Errorf("mock failure")
	})
	defer restore()
	restore = runner.MockUnixMount(func(source string, target string, fstype string, flags uintptr, data string) error {
		return nil
	})
	defer restore()
	restore = runner.MockUnixUnmount(func(target string, flags int) error {
		return nil
	})
	defer restore()
	err := runner.ShimEntry()
	c.Assert(err, ErrorMatches, "exec failed: mock failure")
}

type jcTest struct {
	memoryEventsLocal string
	expectedStop      *runner.Status
}

func (s *runnerSuite) TestJobCycleKill(c *C) {
	s.testJobCycle(c, jcTest{
		expectedStop: &runner.Status{
			Active:     false,
			ExitStatus: -1,
			Signal:     int(syscall.SIGKILL),
		},
	})
}

func (s *runnerSuite) TestJobCycleOOM(c *C) {
	s.testJobCycle(c, jcTest{
		memoryEventsLocal: "oom_group_kill 1",
		expectedStop: &runner.Status{
			Active:     false,
			ExitStatus: -1,
			Signal:     int(syscall.SIGKILL),
			OOM:        true,
		},
	})
}

func (s *runnerSuite) testJobCycle(c *C, tc jcTest) {
	d := c.MkDir()
	scriptPath := filepath.Join(d, "script")
	scriptStamp := filepath.Join(d, "script.stamp")
	testutils.MockFile(c, scriptPath, fmt.Sprintf(`#!/bin/sh
for arg in "$@"; do echo "# $arg" ; done
touch %s
exec sleep 3600
`, scriptStamp))

	c.Assert(os.Chmod(scriptPath, 0755), IsNil)

	testutils.MockFile(c, filepath.Join(d, "proc-self-cgroup"), "0::/foo")
	restore := cgroup.MockProcSelfCgroup(filepath.Join(d, "proc-self-cgroup"))
	defer restore()
	testutils.MockFile(c, filepath.Join(s.cgroupRoot, "foo/cgroup.procs"), "")
	testutils.MockFile(c, filepath.Join(s.cgroupRoot, "foo/cgroup.subtree_control"), "")
	// runner will move the process to this group
	testutils.MockFile(c, filepath.Join(s.cgroupRoot, "foo/runner/cgroup.procs"), "")
	// how the job will be killed
	testutils.MockFile(c, filepath.Join(s.cgroupRoot, "foo/baz/cgroup.kill"), "")
	testutils.MockFile(c, filepath.Join(s.cgroupRoot, "foo/baz/memory.events.local"), tc.memoryEventsLocal)

	restore = cgroup.MockOsRemove(func(p string) error {
		// group removal
		c.Assert(p, Equals, filepath.Join(s.cgroupRoot, "foo/baz"))
		return nil
	})
	defer restore()
	restore = runner.MockProcSelfExe(scriptPath)
	defer restore()

	var hijackedCmd *exec.Cmd
	runner.MockCmdStart(func(cmd *exec.Cmd) error {
		c.Assert(cmd.SysProcAttr, NotNil)
		var uPA *unix.SysProcAttr = cmd.SysProcAttr
		c.Assert(uPA.Cloneflags, Equals, uintptr(unix.CLONE_NEWPID|unix.CLONE_NEWNET|unix.CLONE_NEWNS))
		// clear the flags, as calling with them would require CAP_ADMIN
		cmd.SysProcAttr.Cloneflags = 0
		hijackedCmd = cmd
		err := cmd.Start()
		if err == nil {
			c.Logf("pid: %v", cmd.Process.Pid)
		}
		return err
	})

	r, err := runner.NewCgroupRunner(nil)
	c.Assert(err, IsNil)
	err = r.Start("baz", runner.Config{
		Command: []string{"/bin/ls", "-l"},
	})
	c.Assert(err, IsNil)

	status, err := r.Status("baz")
	c.Logf("status %+v err %v", status, err)
	c.Assert(err, IsNil)
	c.Assert(status, DeepEquals, &runner.Status{
		Active: true,
	})

	now := time.Now()
	for {
		_, err := ioutil.ReadFile(scriptStamp)
		if err == nil {
			break
		}
		if time.Since(now) > 5*time.Second {
			break
		}
		c.Logf("waiting for stamp, since: %v", time.Since(now))
		time.Sleep(time.Second)
	}

	outputReaderChan := make(chan struct{}, 1)
	outChan, cancel, err := r.Output("baz")
	c.Assert(err, IsNil)
	c.Assert(cancel, NotNil)
	c.Assert(outChan, NotNil)

	buf := bytes.Buffer{}
	go func() {
		for chunk := range outChan {
			buf.Write(chunk)
		}
		close(outputReaderChan)
	}()

	// in the meantime, the job's output is already in a file
	testutils.TextFileEquals(c,
		filepath.Join(s.tmpdir, "cgroup-runner-output/baz"),
		`# /bin/ls
# -l
`)

	// stop will block trying to kill the process through cgroups, but since
	// we mocked everything, we need to simulate what cgroups would do
	stopDone := make(chan struct{}, 1)
	go func() {
		c.Logf("stop")
		status, err = r.Stop("baz")
		close(stopDone)

	}()
	c.Logf("killing")
	c.Assert(hijackedCmd.Process, NotNil)
	c.Assert(hijackedCmd.Process.Kill(), IsNil)
	<-stopDone
	c.Logf("stop done")
	c.Assert(err, IsNil)
	c.Assert(status, DeepEquals, tc.expectedStop)

	<-outputReaderChan
	c.Assert(buf.String(), Equals, `# /bin/ls
# -l
`)
}

func (s *runnerSuite) TestJobCycleHappy(c *C) {
	d := c.MkDir()
	scriptPath := filepath.Join(d, "script")
	scriptStamp := filepath.Join(d, "script.stamp")
	testutils.MockFile(c, scriptPath, fmt.Sprintf(`#!/bin/sh
for arg in "$@"; do echo "# $arg" ; done
touch %s
`, scriptStamp))

	c.Assert(os.Chmod(scriptPath, 0755), IsNil)

	testutils.MockFile(c, filepath.Join(d, "proc-self-cgroup"), "0::/foo")
	restore := cgroup.MockProcSelfCgroup(filepath.Join(d, "proc-self-cgroup"))
	defer restore()
	testutils.MockFile(c, filepath.Join(s.cgroupRoot, "foo/cgroup.procs"), "")
	testutils.MockFile(c, filepath.Join(s.cgroupRoot, "foo/cgroup.subtree_control"), "")
	// runner will move the process to this group
	testutils.MockFile(c, filepath.Join(s.cgroupRoot, "foo/runner/cgroup.procs"), "")
	// how the job will be killed
	testutils.MockFile(c, filepath.Join(s.cgroupRoot, "foo/baz/cgroup.kill"), "")
	testutils.MockFile(c, filepath.Join(s.cgroupRoot, "foo/baz/memory.events.local"), "")

	restore = cgroup.MockOsRemove(func(p string) error {
		// group removal
		c.Assert(p, Equals, filepath.Join(s.cgroupRoot, "foo/baz"))
		return nil
	})
	defer restore()
	restore = runner.MockProcSelfExe(scriptPath)
	defer restore()

	var hijackedCmd *exec.Cmd
	runner.MockCmdStart(func(cmd *exec.Cmd) error {
		// clear the flags, as calling with them would require CAP_ADMIN
		cmd.SysProcAttr.Cloneflags = 0
		hijackedCmd = cmd
		return cmd.Start()
	})

	storageDir := c.MkDir()
	r, err := runner.NewCgroupRunner(&runner.RunnerConfig{
		StorageRoot: storageDir,
	})
	c.Assert(err, IsNil)
	err = r.Start("baz", runner.Config{
		Command: []string{"/bin/ls", "-l"},
	})
	c.Assert(err, IsNil)

	now := time.Now()
	for {
		err := syscall.Kill(hijackedCmd.Process.Pid, 0)
		// TODO: this can be flaky is PIDs are reused right away, though
		// they shouldn't
		if err == syscall.ESRCH {
			break
		}
		if time.Since(now) > 5*time.Second {
			break
		}
		c.Logf("waiting for stamp, since: %v", time.Since(now))
		time.Sleep(time.Second)
	}

	expectedStatus := &runner.Status{
		Active:     false,
		Signal:     0,
		ExitStatus: 0,
		OOM:        false,
	}
	// check if the process is alive
	c.Assert(syscall.Kill(hijackedCmd.Process.Pid, 0), Equals, syscall.ESRCH)
	status, err := r.Status("baz")
	c.Logf("status %+v err %v", status, err)
	c.Assert(err, IsNil)
	c.Assert(status, DeepEquals, expectedStatus)

	outputReaderChan := make(chan struct{}, 1)
	outChan, cancel, err := r.Output("baz")
	c.Assert(err, IsNil)
	c.Assert(cancel, NotNil)
	c.Assert(outChan, NotNil)

	buf := bytes.Buffer{}
	go func() {
		for chunk := range outChan {
			buf.Write(chunk)
		}
		close(outputReaderChan)
	}()

	// reading of output will complete now, since the job is already dead
	<-outputReaderChan
	c.Assert(buf.String(), Equals, `# /bin/ls
# -l
`)
	testutils.TextFileEquals(c, filepath.Join(storageDir, "baz"),
		`# /bin/ls
# -l
`)
	// stop will not block on anything
	c.Logf("stop")
	status, err = r.Stop("baz")
	c.Assert(err, IsNil)
	c.Assert(status, DeepEquals, expectedStatus)

}

func (s *runnerSuite) TestJobWithResources(c *C) {
	d := c.MkDir()
	scriptPath := filepath.Join(d, "script")
	scriptStamp := filepath.Join(d, "script.stamp")
	testutils.MockFile(c, scriptPath, fmt.Sprintf(`#!/bin/sh
for arg in "$@"; do echo "# $arg" ; done
touch %s
`, scriptStamp))

	c.Assert(os.Chmod(scriptPath, 0755), IsNil)

	testutils.MockFile(c, filepath.Join(d, "proc-self-cgroup"), "0::/foo")
	restore := cgroup.MockProcSelfCgroup(filepath.Join(d, "proc-self-cgroup"))
	defer restore()
	testutils.MockFile(c, filepath.Join(s.cgroupRoot, "foo/cgroup.procs"), "")
	testutils.MockFile(c, filepath.Join(s.cgroupRoot, "foo/cgroup.subtree_control"), "")
	// runner will move the process to this group
	testutils.MockFile(c, filepath.Join(s.cgroupRoot, "foo/runner/cgroup.procs"), "")
	// paths for the job group
	testutils.MockFile(c, filepath.Join(s.cgroupRoot, "foo/baz/cgroup.kill"), "")
	testutils.MockFile(c, filepath.Join(s.cgroupRoot, "foo/baz/memory.events.local"), "")
	testutils.MockFile(c, filepath.Join(s.cgroupRoot, "foo/baz/cpu.max"), "")
	testutils.MockFile(c, filepath.Join(s.cgroupRoot, "foo/baz/io.max"), "")
	testutils.MockFile(c, filepath.Join(s.cgroupRoot, "foo/baz/memory.max"), "")
	testutils.MockFile(c, filepath.Join(s.cgroupRoot, "foo/baz/memory.oom.group"), "")

	restore = cgroup.MockOsRemove(func(p string) error {
		// group removal
		c.Assert(p, Equals, filepath.Join(s.cgroupRoot, "foo/baz"))
		return nil
	})
	defer restore()
	restore = runner.MockProcSelfExe(scriptPath)
	defer restore()

	runner.MockCmdStart(func(cmd *exec.Cmd) error {
		// do nothing
		return nil
	})

	r, err := runner.NewCgroupRunner(nil)
	c.Assert(err, IsNil)
	err = r.Start("baz", runner.Config{
		Command:   []string{"/bin/ls", "-l"},
		CPUMax:    "200 1000",
		MemoryMax: "102400",
		IOMax:     "8:16 rbps=102400",
	})
	c.Assert(err, IsNil)
	testutils.TextFileEquals(c, filepath.Join(s.cgroupRoot, "foo/baz/cpu.max"),
		"200 1000\n")
	testutils.TextFileEquals(c, filepath.Join(s.cgroupRoot, "foo/baz/io.max"),
		"8:16 rbps=102400\n")
	testutils.TextFileEquals(c, filepath.Join(s.cgroupRoot, "foo/baz/memory.max"),
		"102400\n")
	testutils.TextFileEquals(c, filepath.Join(s.cgroupRoot, "foo/baz/memory.oom.group"),
		"1\n")
}
