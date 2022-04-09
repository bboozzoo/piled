package cgroup

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

var (
	sysFsCgroup = "/sys/fs/cgroup"
	osRemove    = os.Remove
)

// IsV2 returns true if the host is using cgroup v2.
func IsV2() (bool, error) {
	var res unix.Statfs_t
	if err := unix.Statfs(sysFsCgroup, &res); err != nil {
		return false, fmt.Errorf("cannot query filesystem stat: %v", err)
	}
	return res.Type == unix.CGROUP2_SUPER_MAGIC, nil
}

// WriteProperty writes the provided value to the given property.
func WriteProperty(cg, property, value string) error {
	p := filepath.Join(sysFsCgroup, cg, property)
	logrus.Tracef("setting %v to: %q", p, value)
	f, err := os.OpenFile(p, os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("cannot open cgroup property file: %v", err)
	}
	defer f.Close()
	_, err = fmt.Fprintf(f, "%v\n", value)
	return err
}

var KeyNotFoundError = fmt.Errorf("key not found")

// ReadKVProperty returns the value of a given key from the property, eg.
// oom_group_kill from memory.events.local.
func ReadKVProperty(cg, property, key string) (value string, err error) {
	p := filepath.Join(sysFsCgroup, cg, property)
	f, err := os.Open(p)
	if err != nil {
		return "", fmt.Errorf("cannot open cgroup property file: %v", err)
	}
	defer f.Close()
	inf := bufio.NewScanner(f)
	for inf.Scan() {
		// the format is:
		// foo 1\n
		// bar 99\n
		l := strings.TrimSpace(inf.Text())
		if l == "" {
			// bit unexpected
			continue
		}
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
	return "", KeyNotFoundError
}

var procSelfCgroup = "/proc/self/cgroup"

// Current cgroup of the process.
func Current() (string, error) {
	cgNowRaw, err := ioutil.ReadFile(procSelfCgroup)
	if err != nil {
		return "", err
	}
	split := bytes.SplitN(bytes.TrimSpace(cgNowRaw), []byte("::"), 2)
	if len(split) != 2 {
		return "", fmt.Errorf("invalid cgroup content: %v", string(cgNowRaw))
	}
	return string(split[1]), nil
}

// MovePidTo moves the provided pid to a cgroup.
func MovePidTo(pid int, cg string) error {
	return WriteProperty(cg, "cgroup.procs", fmt.Sprintf("%v", pid))
}

// Add a cgroup.
func Add(cg string) error {
	cgPath := filepath.Join(sysFsCgroup, cg)
	return os.MkdirAll(cgPath, 0755)
}

// Remove a cgroup.
func Remove(cg string) error {
	cgPath := filepath.Join(sysFsCgroup, cg)
	return osRemove(cgPath)
}

func Freeze(cg string) error {
	return WriteProperty(cg, "cgroup.freeze", "1")
}

func Unfreeze(cg string) error {
	return WriteProperty(cg, "cgroup.freeze", "0")
}

// Occupied returns true if the cgroup is occupied by at least one process.
func Occupied(cg string) (bool, error) {
	p := filepath.Join(sysFsCgroup, cg, "cgroup.procs")
	f, err := os.Open(p)
	if err != nil {
		return false, fmt.Errorf("cannot open cgroup processes: %v", err)
	}
	defer f.Close()
	buf := [10]byte{}
	_, err = f.Read(buf[:])
	if err == io.EOF || err == nil && len(bytes.TrimSpace(buf[:])) == 0 {
		return false, nil
	} else if err != nil {
		return false, err
	}
	return true, nil
}

// Use only from tests, from cross package mocking
func MockSysFsCgroup(p string) (restore func()) {
	// TODO actually check that we're a test binary
	old := sysFsCgroup
	sysFsCgroup = p
	return func() {
		sysFsCgroup = old
	}
}

// Use only from tests, from cross package mocking
func MockProcSelfCgroup(p string) (restore func()) {
	// TODO actually check that we're a test binary
	old := procSelfCgroup
	procSelfCgroup = p
	return func() {
		procSelfCgroup = old
	}
}

// Use only from tests, from cross package mocking
func MockOsRemove(m func(p string) error) (restore func()) {
	// TODO actually check that we're a test binary
	old := osRemove
	osRemove = m
	return func() {
		osRemove = old
	}
}
