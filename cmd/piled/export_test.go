package main

import (
	"net"

	"github.com/bboozzoo/piled/pile/server"
	"github.com/bboozzoo/piled/runner"
)

type Options = options

var (
	Run = run
)

func MockRunnerNew(m func(_ *runner.RunnerConfig) (server.Runner, error)) (restore func()) {
	old := runnerNew
	runnerNew = m
	return func() {
		runnerNew = old
	}
}

func MockNetListen(m func(string, string) (net.Listener, error)) (restore func()) {
	old := netListen
	netListen = m
	return func() {
		netListen = old
	}
}
