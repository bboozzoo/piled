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
)

var (
	sysFsCgroup = "/sys/fs/cgroup"
)

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

func ReadKVProperty(cg, property, key string) (value string, err error) {
	p := filepath.Join(sysFsCgroup, cg, property)
	f, err := os.Open(p)
	if err != nil {
		return "", fmt.Errorf("cannot open cgroup property file: %v", err)
	}
	defer f.Close()
	inf := bufio.NewScanner(f)
	for inf.Scan() {
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

func MovePidTo(pid int, cg string) error {
	return WriteProperty(cg, "cgroup.procs", fmt.Sprintf("%v", pid))
}

func Add(cg string) error {
	cgPath := filepath.Join(sysFsCgroup, cg)
	return os.MkdirAll(cgPath, 0755)
}

func Remove(cg string) error {
	cgPath := filepath.Join(sysFsCgroup, cg)
	return os.Remove(cgPath)
}

func Freeze(cg string) error {
	return WriteProperty(cg, "cgroup.freeze", "1")
}

func Unfreeze(cg string) error {
	return WriteProperty(cg, "cgroup.freeze", "0")
}

func Occupied(cg string) (bool, error) {
	p := filepath.Join(sysFsCgroup, cg, "cgroup.procs")
	f, err := os.Open(p)
	if err != nil {
		return false, fmt.Errorf("cannot open cgroup property file: %v", err)
	}
	defer f.Close()
	buf := [10]byte{}
	_, err = f.Read(buf[:])
	if err == io.EOF || err == nil && len(bytes.TrimSpace(buf[:])) == 0 {
		// if err != nil {
		return false, nil
	} else if err != nil {
		return false, err
	}
	return true, nil
}
