package runner

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"strconv"

	"github.com/sirupsen/logrus"
)

type systemdRunner struct{}

func NewSystemdRunner() *systemdRunner {
	return &systemdRunner{}
}

type Config struct {
	Command   []string
	CPUMax    string
	IOMax     string
	MemoryMax string
}

func (r *systemdRunner) StartJob(name string, config Config) error {
	if len(config.Command) == 0 {
		return fmt.Errorf("cannot start job without a command")
	}

	// TODO set resources
	args := []string{
		"--no-block",
		"--unit", name + ".service",
		// keep the unit around until stopped
		"--property", "RemainAfterExit=yes",
		// resource accounting
		"--property", "CPUAccounting=yes",
		"--property", "MemoryAccounting=yes",
		"--property", "IOAccounting=yes",
		// isolation
		"--property", "PrivateMounts=yes",
		"--property", "PrivateNetwork=yes",
		"--",
		"unshare", "--cgroup",
		"--",
	}
	args = append(args, config.Command...)
	// TODO use context
	logrus.Tracef("executing: systemctl %v", args)
	cmd := exec.Command("systemd-run", args...)
	if _, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("cannot execute start command: %v", err)
	}
	return nil
}

func (r *systemdRunner) StopJob(name string) error {
	cmd := exec.Command("systemctl", "stop", name+".service")
	if _, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("cannot execute stop command: %v", err)
	}
	// TODO execute clean when the unit failed
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

func (r *systemdRunner) JobStatus(name string) (*Status, error) {
	cmd := exec.Command("systemctl",
		"show",
		"--property", "ActiveState,ExecMainStatus,LoadState,SubState",
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
	if props["SubState"] == "running" {
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

func (r *systemdRunner) Reset(name string) error {
	cmd := exec.Command("systemctl", "reset-failed", name+".service")
	if _, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("cannot reset: %v", err)
	}
	return nil
}

type journalPipe struct {
	ctx       context.Context
	out       chan []byte
	unit      string
	cmd       *exec.Cmd
	cancel    func()
	lineBuf   *bytes.Buffer
	childWait chan struct{}
}

func (j *journalPipe) Write(d []byte) (int, error) {
	logrus.Tracef("write chunk:\n%s", string(d))
	if len(d) == 0 {
		// done
		defer j.cancel()
		return 0, io.EOF
	}
	// logrus.Tracef("accumulated bytes before:\n%s", j.lineBuf.String())
	j.lineBuf.Write(d)
	// logrus.Tracef("accumulated bytes buf:\n%s", j.lineBuf.String())
	b := j.lineBuf.Bytes()
	for {
		if len(b) == 0 {
			j.lineBuf.Truncate(0)
			break
		}
		idx := bytes.IndexByte(b, '\n')
		if idx == -1 {
			// no more newlines

			// NewBuffer() does not copy the bytes, so copy them
			// through a Write() such that we don't loose the buffer
			j.lineBuf = &bytes.Buffer{}
			j.lineBuf.Write(b)
			logrus.Tracef("no newline, chunk:\n%v", j.lineBuf.String())
			break
		}
		// logrus.Tracef("found newline at idx: %v", idx)
		line := b[0:idx]
		logrus.Tracef("line: %s", line)
		b = b[idx+1:]
		var out map[string]string
		if err := json.Unmarshal(line, &out); err != nil {
			logrus.Tracef("error decoding: %v", err)
			defer j.cancel()
			return 0, err
		}
		// logrus.Tracef("got data: %v", out)
		logrus.Tracef("unit: %v", out["_SYSTEMD_UNIT"])
		if out["_SYSTEMD_UNIT"] == j.unit {
			logrus.Tracef("matching unit")
			j.out <- []byte(out["MESSAGE"])
		}
	}

	return len(d), nil
}

func (j *journalPipe) wait() {
	logrus.Tracef("waiting for journalctl")
	if err := j.cmd.Wait(); err != nil {
		logrus.Tracef("wait failed: %v", err)
	}
	j.cancel()
	close(j.childWait)
}

func (j *journalPipe) Process() {
	logrus.Tracef("- waiting for done")
	<-j.ctx.Done()
	logrus.Tracef("- done")
	if err := j.cmd.Process.Kill(); err != nil {
		logrus.Tracef("cannot kill journal: %v", err)
	}
	close(j.out)
	<-j.childWait
}

func (r *systemdRunner) JobOutput(name string) (output chan []byte, cancel func(), err error) {
	// TODO check if unit even exists
	unitName := name + ".service"
	cmd := exec.Command("journalctl",
		"--output", "json",
		"--follow",
		"--unit", unitName)
	ctx, cancel := context.WithCancel(context.Background())
	jp := &journalPipe{
		out:       make(chan []byte, 1),
		ctx:       ctx,
		cmd:       cmd,
		cancel:    cancel,
		unit:      unitName,
		lineBuf:   &bytes.Buffer{},
		childWait: make(chan struct{}, 1),
	}
	cmd.Stdout = jp
	if err := cmd.Start(); err != nil {
		cancel()
		return nil, nil, fmt.Errorf("cannot execute staus command: %v", err)
	}
	go jp.Process()
	go jp.wait()
	return jp.out, cancel, nil
}
