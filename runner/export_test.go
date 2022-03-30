package runner

import (
	"os/exec"
)

func MockUnixExec(m func(argv0 string, argv []string, envv []string) error) (restore func()) {
	old := unixExec
	unixExec = m
	return func() {
		unixExec = old
	}
}

func MockUnixMount(m func(source string, target string, fstype string, flags uintptr, data string) error) (restore func()) {
	old := unixMount
	unixMount = m
	return func() {
		unixMount = old
	}
}

func MockUnixUnmount(m func(target string, flags int) error) (restore func()) {
	old := unixUnmount
	unixUnmount = m
	return func() {
		unixUnmount = old
	}
}

func MockProcSelfExe(m string) (restore func()) {
	old := procSelfExe
	procSelfExe = m
	return func() {
		procSelfExe = old
	}
}

func MockCmdStart(m func(cmd *exec.Cmd) error) (restore func()) {
	old := cmdStart
	cmdStart = m
	return func() {
		cmdStart = old
	}
}

func MockCgroupIsV2(m func() (bool, error)) (restore func()) {
	old := cgroupIsV2
	cgroupIsV2 = m
	return func() {
		cgroupIsV2 = old
	}
}
