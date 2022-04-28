package main_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/bboozzoo/piled/cmd/piled"
	"github.com/bboozzoo/piled/pile/auth"
	pb "github.com/bboozzoo/piled/pile/proto"
	"github.com/bboozzoo/piled/pile/server"
	"github.com/bboozzoo/piled/pile/server/servertest"
	"github.com/bboozzoo/piled/runner"
)

func findFreePort(t *testing.T) string {
	l, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)
	defer l.Close()
	return l.Addr().String()
}

type clientCerts struct {
	Cert, Key string
	CACert    string
}

func client(t *testing.T, addr string, certs clientCerts) (conn *grpc.ClientConn, client pb.JobPileManagerClient) {
	cert, err := tls.LoadX509KeyPair(certs.Cert, certs.Key)
	require.NoError(t, err)
	caCertBytes, err := os.ReadFile(certs.CACert)
	require.NoError(t, err)
	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(caCertBytes))
	creds := credentials.NewTLS(auth.ClientTLSConfig(auth.Config{
		CAPool: pool,
		Cert:   cert,
	}))
	conn, err = grpc.Dial(addr,
		grpc.WithTransportCredentials(creds))
	require.NoError(t, err)
	return conn, pb.NewJobPileManagerClient(conn)
}

func TestSimpleJobCycle(t *testing.T) {
	jobName := "test-job"
	t.Cleanup(main.MockRunnerNew(func(_ *runner.RunnerConfig) (server.Runner, error) {
		return &servertest.MockRunner{
			StartCb: func(_ runner.Config) (string, error) {
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
		}, nil
	}))

	// for syncing with listen in the server
	waitForListen := make(chan struct{})
	var l net.Listener
	t.Cleanup(main.MockNetListen(func(network, address string) (net.Listener, error) {
		listener, err := net.Listen("tcp", "localhost:0")
		require.NoError(t, err)
		l = listener
		defer close(waitForListen)
		return l, nil
	}))
	opt := &main.Options{
		// config which uses testdata/server-{cert,key}.pem and
		// testdata/ca-cert.pem
		Config: "../../testdata/server.yaml",
	}
	// this is racy, but unless something is trying to listen on new ports
	// all the time, it should be fine
	opt.Positional.ListenAddress = "tcp://" + findFreePort(t)

	runDoneC := make(chan error)
	go func() {
		defer close(runDoneC)
		err := main.Run(opt)
		runDoneC <- err
	}()
	// wait until the server reaches listen
	<-waitForListen
	require.NotNil(t, l)
	defer l.Close()
	// make sure that the port is ready to accept
	require.Eventually(t, func() bool {
		c, err := net.Dial("tcp", l.Addr().String())
		if err == nil {
			c.Close()
		}
		return err == nil
	}, time.Second, 5*time.Millisecond)
	t.Logf("ready")

	conn, c := client(t, l.Addr().String(), clientCerts{
		Cert:   "../../testdata/client-cert.pem",
		Key:    "../../testdata/client-key.pem",
		CACert: "../../testdata/ca-cert.pem",
	})
	defer conn.Close()
	res, err := c.Start(context.Background(), &pb.JobStartRequest{
		Token:   "admin-token",
		Command: []string{"/usr/bin/bash", "-c", "echo hello"},
	})
	require.NoError(t, err)
	assert.Equal(t, jobName, res.ID)

	statusRes, err := c.Status(context.Background(), &pb.JobRequest{
		Token: "admin-token",
		ID:    jobName,
	})
	require.NoError(t, err)
	assert.Equal(t, pb.Status_ACTIVE, statusRes.Status.GetStatus())

	stopRes, err := c.Stop(context.Background(), &pb.JobRequest{
		Token: "admin-token",
		ID:    jobName,
	})
	require.NoError(t, err)
	assert.Equal(t, pb.Status_OOM_KILLED, stopRes.Status.GetStatus())

	l.Close()
	err = <-runDoneC
	require.Error(t, err)
	// test closed it, so this is expected
	assert.Contains(t, err.Error(), "use of closed network connection")
}
