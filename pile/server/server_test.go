package server_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"os"
	"syscall"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/test/bufconn"

	"github.com/bboozzoo/piled/pile/auth"
	"github.com/bboozzoo/piled/pile/proto"
	pb "github.com/bboozzoo/piled/pile/proto"
	"github.com/bboozzoo/piled/pile/server"
	"github.com/bboozzoo/piled/runner"
	"github.com/bboozzoo/piled/testutils"
)

type mockRunner struct {
	start  func(config runner.Config) (name string, err error)
	stop   func(name string) (*runner.Status, error)
	status func(name string) (*runner.Status, error)
	output func(name string) (<-chan []byte, func(), error)
}

var errNotImplemnted = errors.New("mock not implemented")

func (m *mockRunner) Start(config runner.Config) (name string, err error) {
	if m.start != nil {
		return m.start(config)
	}
	return "", errNotImplemnted
}

func (m *mockRunner) Stop(name string) (*runner.Status, error) {
	if m.stop != nil {
		return m.stop(name)
	}
	return nil, errNotImplemnted
}
func (m *mockRunner) Status(name string) (*runner.Status, error) {
	if m.status != nil {
		return m.status(name)
	}
	return nil, errNotImplemnted
}

func (m *mockRunner) Output(name string) (output <-chan []byte, cancel func(), err error) {
	if m.output != nil {
		return m.output(name)
	}
	return nil, nil, errNotImplemnted
}

func TestSimpleTokenAuthzStart(t *testing.T) {
	startCalled := 0
	jobName := "pile." + uuid.NewString()
	s := server.NewWithRunner(&mockRunner{
		start: func(_ runner.Config) (string, error) {
			startCalled++
			return jobName, nil
		},
	}).Server()
	res, err := s.Start(context.Background(), &proto.JobStartRequest{
		Token: "bad",
	})
	require.EqualError(t, err, server.NotAuthorizedError.Error())
	require.Nil(t, res)
	assert.Equal(t, 0, startCalled)

	res, err = s.Start(context.Background(), &proto.JobStartRequest{
		Token: "ro-token",
	})
	require.EqualError(t, err, server.NotAuthorizedError.Error())
	require.Nil(t, res)
	assert.Equal(t, 0, startCalled)

	res, err = s.Start(context.Background(), &proto.JobStartRequest{
		Token: "admin-token",
	})
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, 1, startCalled)
	assert.Regexp(t, `pile\.[a-z0-9]+(-[a-z0-9]+)+`, res.ID)
	assert.Equal(t, jobName, res.ID)
}

func TestSimpleJobCycle(t *testing.T) {
	startCalled := 0
	jobName := "job." + uuid.NewString()
	s := server.NewWithRunner(&mockRunner{
		start: func(_ runner.Config) (string, error) {
			startCalled++
			return jobName, nil
		},
		stop: func(name string) (*runner.Status, error) {
			require.Equal(t, jobName, name)
			return &runner.Status{
				Active:     false,
				Signal:     int(syscall.SIGKILL),
				OOM:        true,
				ExitStatus: -1,
			}, nil
		},
		status: func(name string) (*runner.Status, error) {
			require.Equal(t, jobName, name)
			return &runner.Status{
				Active: true,
			}, nil
		},
	}).Server()
	res, err := s.Start(context.Background(), &proto.JobStartRequest{
		Token: "admin-token",
	})
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, 1, startCalled)
	assert.Equal(t, jobName, res.ID)

	statusRes, err := s.Status(context.Background(), &proto.JobRequest{
		Token: "ro-token",
		ID:    res.ID,
	})
	require.NoError(t, err)
	require.NotNil(t, statusRes)
	assert.Equal(t, &pb.StatusResult{
		Status: &pb.Status{
			Status: pb.Status_ACTIVE,
		},
	}, statusRes)

	stopRes, err := s.Stop(context.Background(), &proto.JobRequest{
		Token: "admin-token",
		ID:    res.ID,
	})
	require.NoError(t, err)
	require.NotNil(t, stopRes)
	assert.Equal(t, &pb.StopResult{
		Status: &pb.Status{
			Status:     pb.Status_OOM_KILLED,
			ExitStatus: -1,
			TermSignal: int32(syscall.SIGKILL),
		},
	}, stopRes)

}

type mockOutputServer struct {
	grpc.ServerStream
	ctx  context.Context
	send func(*pb.OutputChunk) error
}

func (m *mockOutputServer) Send(chunk *pb.OutputChunk) error {
	return m.send(chunk)
}

func (m *mockOutputServer) Context() context.Context {
	return m.ctx
}

type testOutputCase struct {
	callCancel bool
}

func testOutput(t *testing.T, tc testOutputCase) {
	startCalled := 0
	// setup a mock output channel, which 3 chunks
	outputChan := make(chan []byte, 3)
	outputChan <- []byte("hello ")
	outputChan <- []byte("from ")
	outputChan <- []byte("test")
	runnerCancelCalls := 0
	// mock cancel which runner.Output() returns
	runnerCancel := func() {
		if !assert.Equal(t, 0, runnerCancelCalls) {
			panic("foo")
		}
		runnerCancelCalls++
		close(outputChan)
	}
	s := server.NewWithRunner(&mockRunner{
		start: func(_ runner.Config) (string, error) {
			startCalled++
			// use something more realistic
			return "pile." + uuid.NewString(), nil
		},
		output: func(name string) (<-chan []byte, func(), error) {
			return outputChan, runnerCancel, nil
		},
	}).Server()
	res, err := s.Start(context.Background(), &proto.JobStartRequest{
		Token: "admin-token",
	})
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, 1, startCalled)
	assert.Regexp(t, `pile\.[a-z0-9]+(-[a-z0-9]+)+`, res.ID)

	var buf bytes.Buffer
	// pretend we're streaming the output, but close channel after sending
	// the last chunk
	outputCtx, outputCancel := context.WithCancel(context.Background())
	sendCalls := 0
	err = s.Output(&pb.JobRequest{
		Token: "ro-token",
		ID:    res.ID,
	}, &mockOutputServer{
		ctx: outputCtx,
		send: func(chunk *pb.OutputChunk) error {
			sendCalls++
			buf.Write(chunk.Chunk)
			if sendCalls == 3 {
				if tc.callCancel {
					// pretend that the called has canceled the call
					// due for eg. connection interrupt
					outputCancel()
				} else {
					// pretend output is complete and the
					// job has finished
					close(outputChan)
				}
			}
			return nil
		},
	})
	if tc.callCancel {
		require.Error(t, err, context.Canceled)
		// the server's output called the runner's cancel when its context was
		// canceled
		assert.Equal(t, 1, runnerCancelCalls)
	} else {
		require.NoError(t, err)
		assert.Equal(t, 0, runnerCancelCalls)
	}
	assert.Equal(t, "hello from test", buf.String())
	assert.Equal(t, 3, sendCalls)
}

func TestOutput(t *testing.T) {
	t.Run("with_cancel", func(t *testing.T) {
		testOutput(t, testOutputCase{
			callCancel: true,
		})
	})
	t.Run("collect_all", func(t *testing.T) {
		testOutput(t, testOutputCase{
			callCancel: false,
		})
	})
}

type testDataSet struct {
	CAFile                string
	ClientCert, ClientKey string
	ServerCert, ServerKey string
}

func testData(t *testing.T, tds testDataSet) (CAPool *x509.CertPool, server, client tls.Certificate) {
	client, err := tls.LoadX509KeyPair(tds.ClientCert, tds.ClientKey)
	require.NoError(t, err)
	server, err = tls.LoadX509KeyPair(tds.ServerCert, tds.ServerKey)
	require.NoError(t, err)
	pool := x509.NewCertPool()
	d, err := os.ReadFile(tds.CAFile)
	require.NoError(t, err)
	pool.AppendCertsFromPEM(d)
	return pool, server, client
}

type serverCertTestCase struct {
	tds   testDataSet
	valid bool
	log   string
}

func testServeValidCerts(t *testing.T, tc serverCertTestCase) {
	logBuf := testutils.MockLogger(t)
	pool, serverCert, clientCert := testData(t, tc.tds)
	s := server.NewWithRunner(&mockRunner{
		start: func(config runner.Config) (name string, err error) {
			return "1234", nil
		},
	})
	l := bufconn.Listen(4096)
	defer l.Close()
	ac := auth.Config{
		CAPool: pool,
		Cert:   serverCert,
	}
	closeC := make(chan struct{})
	serveCtx, serveCancel := context.WithCancel(context.Background())
	go func() {
		err := s.Serve(serveCtx, l, ac)
		require.NoError(t, err)
		t.Logf("serve done")
		close(closeC)
	}()
	dial := func(context.Context, string) (net.Conn, error) {
		return l.Dial()
	}
	var gotServerCert *x509.Certificate
	creds := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{clientCert},
		MinVersion:   tls.VersionTLS13,
		// do our own verification instead
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			assert.Len(t, cs.PeerCertificates, 1)
			gotServerCert = cs.PeerCertificates[0]
			return nil
		},
	})

	conn, err := grpc.Dial("",
		grpc.WithContextDialer(dial),
		grpc.WithTransportCredentials(creds))
	require.NoError(t, err)
	defer conn.Close()
	c := pb.NewJobPileManagerClient(conn)
	res, err := c.Start(context.Background(), &pb.JobStartRequest{
		Token:   "admin-token",
		Command: []string{"ls", "-l"},
	})
	if tc.valid {
		require.NoError(t, err)
		require.NotNil(t, res)
		assert.Equal(t, "1234", res.ID)
	} else {
		t.Logf("err: %v", err)
		require.Error(t, err)
		assert.Contains(t, err.Error(), " connection closed before server preface received")
	}
	// verify that the server certificate is the same as passed in the
	// config
	require.NotNil(t, gotServerCert)
	wantServerCert, err := x509.ParseCertificate(serverCert.Certificate[0])
	require.NoError(t, err)
	assert.True(t, wantServerCert.Equal(gotServerCert))

	serveCancel()
	<-closeC

	if tc.log != "" {
		assert.Contains(t, logBuf.String(), tc.log)
	} else {
		assert.Empty(t, logBuf.String())
	}
}

func TestServerCertValidation(t *testing.T) {
	t.Run("valid_cert", func(t *testing.T) {
		testServeValidCerts(t, serverCertTestCase{
			tds: testDataSet{
				CAFile:     "../../testdata/ca-cert.pem",
				ClientCert: "../../testdata/client-cert.pem",
				ClientKey:  "../../testdata/client-key.pem",
				ServerCert: "../../testdata/server-cert.pem",
				ServerKey:  "../../testdata/server-key.pem",
			},
			valid: true,
		})
	})
	t.Run("invalid_cert", func(t *testing.T) {
		testServeValidCerts(t, serverCertTestCase{
			tds: testDataSet{
				CAFile:     "../../testdata/ca-cert.pem",
				ClientCert: "../../testdata/invalid-client-cert.pem",
				ClientKey:  "../../testdata/invalid-client-key.pem",
				ServerCert: "../../testdata/server-cert.pem",
				ServerKey:  "../../testdata/server-key.pem",
			},
			valid: false,
		})
	})
	t.Run("valid_cert_not_pilec", func(t *testing.T) {
		testServeValidCerts(t, serverCertTestCase{
			tds: testDataSet{
				CAFile:     "../../testdata/ca-cert.pem",
				ClientCert: "../../testdata/client-not-pilec-cert.pem",
				ClientKey:  "../../testdata/client-key.pem",
				ServerCert: "../../testdata/server-cert.pem",
				ServerKey:  "../../testdata/server-key.pem",
			},
			valid: false,
			// quotes in a message are escaped
			log: `expected certificate of pilec not \"CN=not-pilec,O=pile\"`,
		})
	})
}

func TestAuthorization(t *testing.T) {
	type opsAuthz struct {
		ok    []string
		notOk []string
	}
	tokensAndOps := map[string]opsAuthz{
		"admin-token": {
			ok: []string{"start", "stop", "status", "output"},
		},
		"ro-token": {
			ok:    []string{"status", "output"},
			notOk: []string{"start", "stop"},
		},
		"unknown-token": {
			notOk: []string{"start", "stop", "status", "output"},
		},
	}

	s := server.NewWithRunner(&mockRunner{})

	for tok, ops := range tokensAndOps {
		for _, op := range ops.ok {
			err := s.OpAuthorized(tok, op)
			assert.NoError(t, err, "tok %v op: %v", tok, op)
		}
		for _, op := range ops.notOk {
			err := s.OpAuthorized(tok, op)
			assert.EqualError(t, err, server.NotAuthorizedError.Error(),
				"tok: %v op: %v", tok, op)
		}
	}
}
