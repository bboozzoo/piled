package runner

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os/exec"
	"strconv"

	"github.com/sirupsen/logrus"
)

type Config struct {
	Command []string
	CPU     string
	IO      string
}

func StartJob(name string, config Config) error {
	if len(config.Command) == 0 {
		return fmt.Errorf("cannot start job without a command")
	}

	args := []string{
		"--no-block",
		"--unit", name + ".service",
		"--property", "CPUAccounting=yes",
		"--property", "MemoryAccounting=yes",
		"--property", "IOAccounting=yes",
		"--",
	}
	// TODO set resources
	args = append(args, config.Command...)
	// TODO use context
	logrus.Tracef("executing: systemctl %v", args)
	cmd := exec.Command("systemd-run", args...)
	if _, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("cannot execute start command: %v", err)
	}
	return nil
}

func StopJob(name string) error {
	cmd := exec.Command("systemctl", "stop", name+".service")
	if _, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("cannot execute stop command: %v", err)
	}
	return nil
}

type Status struct {
	Present    bool
	Active     bool
	ExitStatus int
}

func showToDict(out []byte) (props map[string]string, err error) {
	r := bufio.NewReader(bytes.NewReader(out))
	for {
		l, _, err := r.ReadLine()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		fields := bytes.SplitN(bytes.TrimSpace(l), []byte("="), 2)
		if len(fields) != 2 {
			return nil, fmt.Errorf("cannot process line: %q", string(l))
		}
		if props == nil {
			props = make(map[string]string)
		}
		props[string(fields[0])] = string(fields[1])
	}
	logrus.Tracef("props: %v", props)
	return props, nil
}

func JobStatus(name string) (*Status, error) {
	cmd := exec.Command("systemctl",
		"show",
		"--property", "ActiveState,ExecMainStatus",
		name+".service")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("cannot execute staus command: %v", err)
	}
	props, err := showToDict(out)
	if err != nil {
		return nil, fmt.Errorf("cannot process status output: %v", err)
	}

	status := Status{}
	if props["ActiveState"] == "active" {
		status.Active = true
	}
	if props["LoadState"] == "loaded" {
		status.Present = true
	}
	if exitStatus := props["ExecMainStatus"]; exitStatus != "" {
		numStatus, err := strconv.Atoi(exitStatus)
		if err != nil {
			return nil, fmt.Errorf("cannot process exit status %q: %v", exitStatus, err)
		}
		status.ExitStatus = numStatus
	}
	return &status, nil
}

func JobOutput(jobID string) (output chan []byte, cancel func(), err error) {
	return nil, nil, nil
}
