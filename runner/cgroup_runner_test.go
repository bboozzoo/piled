package runner_test

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/bboozzoo/piled/cgroup"
	"github.com/bboozzoo/piled/runner"
	"github.com/bboozzoo/piled/testutils"
)

func setUpTest(t *testing.T) string {
	cgroupRoot := t.TempDir()

	restore := runner.MockUnixExec(func(argv0 string, argv []string, envv []string) error {
		t.Fatalf("unixExec not mocked")
		return fmt.Errorf("unexpected call")
	})
	t.Cleanup(restore)
	restore = cgroup.MockSysFsCgroup(cgroupRoot)
	t.Cleanup(restore)

	tmp := t.TempDir()
	oldTmp, wasSet := os.LookupEnv("TMPDIR")
	os.Setenv("TMPDIR", tmp)
	t.Cleanup(func() {
		if wasSet {
			os.Setenv("TMPDIR", oldTmp)
		} else {
			os.Unsetenv("TMPDIR")
		}
	})
	t.Cleanup(runner.MockCgroupIsV2(func() (bool, error) {
		return true, nil
	}))
	return cgroupRoot
}

func TestIsShimEntry(t *testing.T) {
	setUpTest(t)
	is := runner.IsShimEntry()
	assert.False(t, is)

	os.Setenv("_SHIM_IN_NAMESPACE", "1")
	defer os.Unsetenv("_SHIM_IN_NAMESPACE")

	is = runner.IsShimEntry()
	assert.True(t, is)
}

func TestShimEntryHappy(t *testing.T) {
	cgroupRoot := setUpTest(t)

	os.Setenv("_SHIM_IN_NAMESPACE", "1")
	defer os.Unsetenv("_SHIM_IN_NAMESPACE")
	os.Setenv("_SHIM_CG", "/foo/bar/baz")
	defer os.Unsetenv("_SHIM_CG")

	testutils.MockFile(t, filepath.Join(cgroupRoot, "/foo/bar/baz/cgroup.procs"), "")

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
		require.EqualValues(t, []string{
			// / was already remounted
			`/ -> / type:""`,
		}, mounts)
		umounts = append(umounts, target)
		return nil
	})
	defer restore()

	err := runner.ShimEntry()
	require.NoError(t, err)
	assert.Equal(t, 1, execCalls)

	assert.EqualValues(t, []string{
		// / was already remounted
		`/ -> / type:""`,
		`proc -> /proc type:"proc"`,
	}, mounts)
	assert.EqualValues(t, []string{
		"/proc",
	}, umounts)
}

func TestShimEntryExecFails(t *testing.T) {
	cgroupRoot := setUpTest(t)

	os.Setenv("_SHIM_IN_NAMESPACE", "1")
	defer os.Unsetenv("_SHIM_IN_NAMESPACE")
	os.Setenv("_SHIM_CG", "/foo/bar/baz")
	defer os.Unsetenv("_SHIM_CG")

	testutils.MockFile(t, filepath.Join(cgroupRoot, "/foo/bar/baz/cgroup.procs"), "")

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
	require.Error(t, err)
	assert.EqualError(t, err, "exec failed: mock failure")
}

type jcTest struct {
	memoryEventsLocal string
	expectedStop      *runner.Status
}

func TestJobCycleKill(t *testing.T) {
	testJobCycle(t, jcTest{
		expectedStop: &runner.Status{
			Active:     false,
			ExitStatus: -1,
			Signal:     int(syscall.SIGKILL),
		},
	})
}

func TestJobCycleOOM(t *testing.T) {
	testJobCycle(t, jcTest{
		memoryEventsLocal: "oom_group_kill 1",
		expectedStop: &runner.Status{
			Active:     false,
			ExitStatus: -1,
			Signal:     int(syscall.SIGKILL),
			OOM:        true,
		},
	})
}

func testJobCycle(t *testing.T, tc jcTest) {
	cgroupRoot := setUpTest(t)
	d := t.TempDir()

	scriptPath := filepath.Join(d, "script")
	scriptStamp := filepath.Join(d, "script.stamp")
	testutils.MockFile(t, scriptPath, fmt.Sprintf(`#!/bin/sh
for arg in "$@"; do echo "# $arg" ; done
touch %s
exec sleep 3600
`, scriptStamp))

	require.NoError(t, os.Chmod(scriptPath, 0755))

	testutils.MockFile(t, filepath.Join(d, "proc-self-cgroup"), "0::/foo")
	restore := cgroup.MockProcSelfCgroup(filepath.Join(d, "proc-self-cgroup"))
	defer restore()
	testutils.MockFile(t, filepath.Join(cgroupRoot, "foo/cgroup.procs"), "")
	testutils.MockFile(t, filepath.Join(cgroupRoot, "foo/cgroup.subtree_control"), "")
	// runner will move the process to this group
	testutils.MockFile(t, filepath.Join(cgroupRoot, "foo/runner/cgroup.procs"), "")
	// how the job will be killed
	testutils.MockFile(t, filepath.Join(cgroupRoot, "foo/baz/cgroup.kill"), "")
	testutils.MockFile(t, filepath.Join(cgroupRoot, "foo/baz/memory.events.local"), tc.memoryEventsLocal)

	restore = cgroup.MockOsRemove(func(p string) error {
		// group removal
		require.Equal(t, filepath.Join(cgroupRoot, "foo/baz"), p)
		return nil
	})
	defer restore()
	restore = runner.MockProcSelfExe(scriptPath)
	defer restore()

	var hijackedCmd *exec.Cmd
	runner.MockCmdStart(func(cmd *exec.Cmd) error {
		require.NotNil(t, cmd.SysProcAttr)
		var uPA *unix.SysProcAttr = cmd.SysProcAttr
		assert.Equal(t, uintptr(unix.CLONE_NEWPID|unix.CLONE_NEWNET|unix.CLONE_NEWNS), uPA.Cloneflags)
		// clear the flags, as calling with them would require CAP_ADMIN
		cmd.SysProcAttr.Cloneflags = 0
		hijackedCmd = cmd
		err := cmd.Start()
		if err == nil {
			t.Logf("pid: %v", cmd.Process.Pid)
		}
		return err
	})

	r, err := runner.NewCgroupRunner(nil)
	require.NoError(t, err)
	err = r.Start("baz", runner.Config{
		Command: []string{"/bin/ls", "-l"},
	})
	require.NoError(t, err)

	status, err := r.Status("baz")
	t.Logf("status %+v err %v", status, err)
	require.NoError(t, err)
	assert.Equal(t, &runner.Status{
		Active: true,
	}, status)

	// wait until the stamp file appears
	require.Eventually(t, func() bool {
		_, err := os.ReadFile(scriptStamp)
		return err == nil
	}, 5*time.Second, 100*time.Millisecond)

	outputReaderChan := make(chan struct{}, 1)
	outChan, cancel, err := r.Output("baz")
	require.NoError(t, err)
	require.NotNil(t, cancel)
	require.NotNil(t, outChan)

	buf := bytes.Buffer{}
	go func() {
		for chunk := range outChan {
			buf.Write(chunk)
		}
		close(outputReaderChan)
	}()

	expectedOutput := `# /bin/ls
# -l
`

	// stop will block trying to kill the process through cgroups, but since
	// we mocked everything, we need to simulate what cgroups would do
	stopDone := make(chan struct{}, 1)
	go func() {
		t.Logf("stop")
		status, err = r.Stop("baz")
		close(stopDone)

	}()
	t.Logf("killing")
	require.NotNil(t, hijackedCmd.Process)
	require.NoError(t, hijackedCmd.Process.Kill())
	<-stopDone
	t.Logf("stop done")
	require.NoError(t, err)
	assert.Equal(t, tc.expectedStop, status)

	<-outputReaderChan
	assert.Equal(t, expectedOutput, buf.String())
}

func TestJobCycleHappy(t *testing.T) {
	cgroupRoot := setUpTest(t)
	d := t.TempDir()
	scriptPath := filepath.Join(d, "script")
	scriptStamp := filepath.Join(d, "script.stamp")
	testutils.MockFile(t, scriptPath, fmt.Sprintf(`#!/bin/sh
for arg in "$@"; do echo "# $arg" ; done
touch %s
`, scriptStamp))

	require.NoError(t, os.Chmod(scriptPath, 0755))

	testutils.MockFile(t, filepath.Join(d, "proc-self-cgroup"), "0::/foo")
	restore := cgroup.MockProcSelfCgroup(filepath.Join(d, "proc-self-cgroup"))
	defer restore()
	testutils.MockFile(t, filepath.Join(cgroupRoot, "foo/cgroup.procs"), "")
	testutils.MockFile(t, filepath.Join(cgroupRoot, "foo/cgroup.subtree_control"), "")
	// runner will move the process to this group
	testutils.MockFile(t, filepath.Join(cgroupRoot, "foo/runner/cgroup.procs"), "")
	// how the job will be killed
	testutils.MockFile(t, filepath.Join(cgroupRoot, "foo/baz/cgroup.kill"), "")
	testutils.MockFile(t, filepath.Join(cgroupRoot, "foo/baz/memory.events.local"), "")

	restore = cgroup.MockOsRemove(func(p string) error {
		// group removal
		require.Equal(t, filepath.Join(cgroupRoot, "foo/baz"), p)
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

	storageDir := t.TempDir()
	r, err := runner.NewCgroupRunner(&runner.RunnerConfig{
		StorageRoot: storageDir,
	})
	require.NoError(t, err)
	err = r.Start("baz", runner.Config{
		Command: []string{"/bin/ls", "-l"},
	})
	require.NoError(t, err)

	// waitn until the process is gone
	require.Eventually(t, func() bool {
		err := syscall.Kill(hijackedCmd.Process.Pid, 0)
		return err == syscall.ESRCH
	}, 5*time.Second, 100*time.Millisecond)

	expectedStatus := &runner.Status{
		Active:     false,
		Signal:     0,
		ExitStatus: 0,
		OOM:        false,
	}
	// check if the process is alive
	require.Equal(t, syscall.ESRCH, syscall.Kill(hijackedCmd.Process.Pid, 0))
	status, err := r.Status("baz")
	t.Logf("status %+v err %v", status, err)
	require.NoError(t, err)
	assert.Equal(t, expectedStatus, status)

	outputReaderChan := make(chan struct{}, 1)
	outChan, cancel, err := r.Output("baz")
	require.NoError(t, err)
	require.NotNil(t, cancel)
	require.NotNil(t, outChan)

	buf := bytes.Buffer{}
	go func() {
		for chunk := range outChan {
			buf.Write(chunk)
		}
		close(outputReaderChan)
	}()

	// reading of output will complete now, since the job is already dead
	<-outputReaderChan
	expectedOutput := `# /bin/ls
# -l
`
	require.Equal(t, expectedOutput, buf.String())
	testutils.TextFileEquals(t, filepath.Join(storageDir, "baz"), expectedOutput)
	// stop will not block on anything
	t.Logf("stop")
	status, err = r.Stop("baz")
	require.NoError(t, err)
	assert.Equal(t, expectedStatus, status)

}

func TestJobWithResources(t *testing.T) {
	cgroupRoot := setUpTest(t)
	d := t.TempDir()
	scriptPath := filepath.Join(d, "script")
	scriptStamp := filepath.Join(d, "script.stamp")
	testutils.MockFile(t, scriptPath, fmt.Sprintf(`#!/bin/sh
for arg in "$@"; do echo "# $arg" ; done
touch %s
`, scriptStamp))

	require.NoError(t, os.Chmod(scriptPath, 0755))

	testutils.MockFile(t, filepath.Join(d, "proc-self-cgroup"), "0::/foo")
	restore := cgroup.MockProcSelfCgroup(filepath.Join(d, "proc-self-cgroup"))
	defer restore()
	testutils.MockFile(t, filepath.Join(cgroupRoot, "foo/cgroup.procs"), "")
	testutils.MockFile(t, filepath.Join(cgroupRoot, "foo/cgroup.subtree_control"), "")
	// runner will move the process to this group
	testutils.MockFile(t, filepath.Join(cgroupRoot, "foo/runner/cgroup.procs"), "")
	// paths for the job group
	testutils.MockFile(t, filepath.Join(cgroupRoot, "foo/baz/cgroup.kill"), "")
	testutils.MockFile(t, filepath.Join(cgroupRoot, "foo/baz/memory.events.local"), "")
	testutils.MockFile(t, filepath.Join(cgroupRoot, "foo/baz/cpu.max"), "")
	testutils.MockFile(t, filepath.Join(cgroupRoot, "foo/baz/io.max"), "")
	testutils.MockFile(t, filepath.Join(cgroupRoot, "foo/baz/memory.max"), "")
	testutils.MockFile(t, filepath.Join(cgroupRoot, "foo/baz/memory.oom.group"), "")

	restore = cgroup.MockOsRemove(func(p string) error {
		// group removal
		require.Equal(t, filepath.Join(cgroupRoot, "foo/baz"), p)
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
	require.NoError(t, err)
	err = r.Start("baz", runner.Config{
		Command:   []string{"/bin/ls", "-l"},
		CPUMax:    "200 1000",
		MemoryMax: "102400",
		IOMax:     "8:16 rbps=102400",
	})
	require.NoError(t, err)
	testutils.TextFileEquals(t, filepath.Join(cgroupRoot, "foo/baz/cpu.max"),
		"200 1000\n")
	testutils.TextFileEquals(t, filepath.Join(cgroupRoot, "foo/baz/io.max"),
		"8:16 rbps=102400\n")
	testutils.TextFileEquals(t, filepath.Join(cgroupRoot, "foo/baz/memory.max"),
		"102400\n")
	testutils.TextFileEquals(t, filepath.Join(cgroupRoot, "foo/baz/memory.oom.group"),
		"1\n")
}
