package server_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
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

var (
	validCertsSet = testCertSet{
		CAFile:     "../../testdata/ca-cert.pem",
		ClientCert: "../../testdata/client-cert.pem",
		ClientKey:  "../../testdata/client-key.pem",
		ServerCert: "../../testdata/server-cert.pem",
		ServerKey:  "../../testdata/server-key.pem",
	}
)

func TestSimpleTokenAuthz(t *testing.T) {
	startCalled := 0
	jobName := "pile." + uuid.NewString()
	s := server.NewWithRunner(&mockRunner{
		start: func(_ runner.Config) (string, error) {
			startCalled++
			return jobName, nil
		},
		status: func(name string) (*runner.Status, error) {
			require.Equal(t, jobName, name)
			return &runner.Status{
				Active: true,
			}, nil
		},
	})
	lcf := listenAndConnect(t, s, validCertsSet)
	defer lcf.Close()

	c := pb.NewJobPileManagerClient(lcf.conn)

	notAuthorized := `rpc error: code = PermissionDenied desc = error: not authorized`
	for _, tc := range []struct {
		tok      string
		startOk  bool
		statusOk bool
	}{
		{tok: "bad"},
		{tok: "ro-token", statusOk: true},
		{tok: "admin-token", startOk: true, statusOk: true},
	} {
		startCalled = 0
		res, err := c.Start(context.Background(), &proto.JobStartRequest{
			Token: tc.tok,
		})
		if tc.startOk {
			require.NoError(t, err)
			require.NotNil(t, res)
			assert.Equal(t, 1, startCalled)
			assert.Equal(t, jobName, res.ID)
		} else {
			require.EqualError(t, err, notAuthorized)
			require.Nil(t, res)
			assert.Equal(t, 0, startCalled)
		}
		_, err = c.Status(context.Background(), &proto.JobRequest{
			Token: tc.tok,
			ID:    jobName,
		})
		if tc.statusOk {
			require.NoError(t, err)
		} else {
			require.EqualError(t, err, notAuthorized)
			require.Nil(t, res)
			assert.Equal(t, 0, startCalled)
		}
	}
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
	})
	lcf := listenAndConnect(t, s, validCertsSet)
	defer lcf.Close()
	c := pb.NewJobPileManagerClient(lcf.conn)
	res, err := c.Start(context.Background(), &proto.JobStartRequest{
		Token: "admin-token",
	})
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, 1, startCalled)
	assert.Equal(t, jobName, res.ID)

	statusRes, err := c.Status(context.Background(), &proto.JobRequest{
		Token: "ro-token",
		ID:    res.ID,
	})
	require.NoError(t, err)
	require.NotNil(t, statusRes)
	assert.Equal(t, pb.Status_ACTIVE, statusRes.Status.Status)

	stopRes, err := c.Stop(context.Background(), &proto.JobRequest{
		Token: "admin-token",
		ID:    res.ID,
	})
	require.NoError(t, err)
	require.NotNil(t, stopRes)
	assert.Equal(t, pb.Status_OOM_KILLED, stopRes.Status.Status)
	assert.Equal(t, int32(-1), stopRes.Status.ExitStatus)
	assert.Equal(t, int32(syscall.SIGKILL), stopRes.Status.TermSignal)
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
	})
	lcf := listenAndConnect(t, s, validCertsSet)
	defer lcf.Close()
	c := pb.NewJobPileManagerClient(lcf.conn)

	res, err := c.Start(context.Background(), &proto.JobStartRequest{
		Token: "admin-token",
	})
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, 1, startCalled)
	assert.Regexp(t, `pile\.[a-z0-9]+(-[a-z0-9]+)+`, res.ID)

	var buf bytes.Buffer
	outputCtx, outputCancel := context.WithCancel(context.Background())
	outc, err := c.Output(outputCtx, &pb.JobRequest{
		Token: "ro-token",
		ID:    res.ID,
	})
	require.NoError(t, err)
	// 3 chunks were buffered
	for i := 0; i < 3; i++ {
		chunk, err := outc.Recv()
		require.NoError(t, err)
		buf.Write(chunk.Chunk)
	}
	if tc.callCancel {
		outputCancel()
		_, err := outc.Recv()
		require.Error(t, err, context.Canceled)
	} else {
		// pretend the job is done
		close(outputChan)
		// should not block, the server part is expected to close the
		// connection
		_, err := outc.Recv()
		require.Error(t, err, io.EOF)
		assert.Equal(t, 0, runnerCancelCalls)
		outputCancel()
	}
	assert.Equal(t, "hello from test", buf.String())
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

type testCertSet struct {
	CAFile                string
	ClientCert, ClientKey string
	ServerCert, ServerKey string
}

func testCerts(t *testing.T, tds testCertSet) (CAPool *x509.CertPool, server, client tls.Certificate) {
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

type listenConnectFixture struct {
	listener    net.Listener
	conn        *grpc.ClientConn
	serveCancel func()
	closeC      chan struct{}
}

func (l *listenConnectFixture) Close() {
	l.serveCancel()
	<-l.closeC
	l.conn.Close()
	l.listener.Close()
}

func listenAndConnect(t *testing.T, server *server.PileServer, tds testCertSet) listenConnectFixture {
	pool, serverCert, clientCert := testCerts(t, tds)
	wantServerCert, err := x509.ParseCertificate(serverCert.Certificate[0])
	require.NoError(t, err)

	l := bufconn.Listen(4096)
	ac := auth.Config{
		CAPool: pool,
		Cert:   serverCert,
	}
	closeC := make(chan struct{})
	serveCtx, serveCancel := context.WithCancel(context.Background())
	go func() {
		err := server.Serve(serveCtx, l, ac)
		require.NoError(t, err)
		t.Logf("serve done")
		close(closeC)
	}()
	dial := func(context.Context, string) (net.Conn, error) {
		return l.Dial()
	}
	creds := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{clientCert},
		MinVersion:   tls.VersionTLS13,
		// do our own verification instead
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			assert.Len(t, cs.PeerCertificates, 1)
			gotServerCert := cs.PeerCertificates[0]
			assert.True(t, wantServerCert.Equal(gotServerCert))
			return nil
		},
	})

	conn, err := grpc.Dial("",
		grpc.WithContextDialer(dial),
		grpc.WithTransportCredentials(creds))
	require.NoError(t, err)

	return listenConnectFixture{
		listener:    l,
		conn:        conn,
		serveCancel: serveCancel,
		closeC:      closeC,
	}
}

type serverCertTestCase struct {
	tds   testCertSet
	valid bool
	log   string
}

func testServeValidCerts(t *testing.T, tc serverCertTestCase) {
	logBuf := testutils.MockLogger(t)
	s := server.NewWithRunner(&mockRunner{
		start: func(config runner.Config) (name string, err error) {
			return "1234", nil
		},
	})
	lcf := listenAndConnect(t, s, tc.tds)
	defer lcf.Close()

	c := pb.NewJobPileManagerClient(lcf.conn)
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

	if tc.log != "" {
		assert.Contains(t, logBuf.String(), tc.log)
	} else {
		assert.Empty(t, logBuf.String())
	}
}

func TestServerCertValidation(t *testing.T) {
	t.Run("valid_cert", func(t *testing.T) {
		testServeValidCerts(t, serverCertTestCase{
			tds: testCertSet{
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
			tds: testCertSet{
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
			tds: testCertSet{
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
