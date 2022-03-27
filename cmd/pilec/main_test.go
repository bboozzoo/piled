package main_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bboozzoo/piled/cmd/pilec"
	"github.com/bboozzoo/piled/pile/auth"
	"github.com/bboozzoo/piled/pile/server"
	"github.com/bboozzoo/piled/pile/server/servertest"
	"github.com/bboozzoo/piled/runner"
)

type serverCerts struct {
	Cert, Key string
	CACert    string
}

func serverAuth(t *testing.T, certs serverCerts) auth.Config {
	cert, err := tls.LoadX509KeyPair(certs.Cert, certs.Key)
	require.NoError(t, err)
	caCertBytes, err := os.ReadFile(certs.CACert)
	require.NoError(t, err)
	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(caCertBytes))
	return auth.Config{
		CAPool: pool,
		Cert:   cert,
	}
}

func TestSimpleJobCycle(t *testing.T) {
	jobName := "test-job"
	outputC := make(chan []byte, 3)
	outputC <- []byte("hello\n")
	outputC <- []byte("from\n")
	outputC <- []byte("job\n")
	close(outputC)
	s := server.NewWithRunner(&servertest.MockRunner{
		StartCb: func(runner.Config) (string, error) {
			t.Logf("start called")
			return jobName, nil
		},
		StopCb: func(name string) (*runner.Status, error) {
			require.Equal(t, jobName, name)
			return &runner.Status{
				Active:     false,
				Signal:     int(syscall.SIGKILL),
				OOM:        true,
				ExitStatus: -1,
			}, nil
		},
		StatusCb: func(name string) (*runner.Status, error) {
			require.Equal(t, jobName, name)
			return &runner.Status{
				Active: true,
			}, nil
		},
		OutputCb: func(name string) (<-chan []byte, func(), error) {
			return outputC, func() {}, nil
		},
	})
	l, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)
	defer l.Close()

	serveDoneC := make(chan error)
	serveCtx, serveCancel := context.WithCancel(context.Background())
	go func() {
		err := s.Serve(serveCtx, l,
			serverAuth(t, serverCerts{
				Cert:   "../../testdata/server-cert.pem",
				Key:    "../../testdata/server-key.pem",
				CACert: "../../testdata/ca-cert.pem",
			}))
		serveDoneC <- err
	}()

	buf := &bytes.Buffer{}
	t.Cleanup(main.MockStdout(buf))

	p := main.Parser()
	_, err = p.ParseArgs([]string{"--config", "../../testdata/client.yaml",
		// override address
		"--address", "dns:" + l.Addr().String(),
		// override token
		"--token", "admin-token",
		"start", "--", "hello"})
	require.NoError(t, err)
	assert.Equal(t, "test-job\n", buf.String())

	buf.Reset()
	_, err = p.ParseArgs([]string{"--config", "../../testdata/client.yaml",
		"--address", "dns:" + l.Addr().String(),
		"status", "test-job"})
	require.NoError(t, err)
	assert.Equal(t, "active\n", buf.String())

	buf.Reset()
	_, err = p.ParseArgs([]string{"--config", "../../testdata/client.yaml",
		"--address", "dns:" + l.Addr().String(),
		"--token", "admin-token",
		"stop", "test-job"})
	require.NoError(t, err)
	assert.Equal(t, "oom-kill (status=-1,signal=9)\n", buf.String())

	buf.Reset()
	_, err = p.ParseArgs([]string{"--config", "../../testdata/client.yaml",
		"--address", "dns:" + l.Addr().String(),
		"--token", "admin-token",
		"output", "test-job"})
	require.NoError(t, err)
	assert.Equal(t, "hello\nfrom\njob\n", buf.String())

	serveCancel()
	err = <-serveDoneC
	require.NoError(t, err)
}
