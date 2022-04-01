package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/jessevdk/go-flags"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	pb "github.com/bboozzoo/piled/pile/proto"
	"github.com/bboozzoo/piled/utils"
)

type cmdStart struct {
	MemoryMax uint64 `long:"memory-max" description:"Max memory for this job"`
	CPUWeight uint   `long:"cpu-weight" description:"CPU weight of this job"`
	IOWeight  uint   `long:"io-weight" description:"IO weight of this job"`

	Positional struct {
		Args []string `positional-arg-name:"arg" required:"1"`
	} `positional-args:"yes"`
}

type cmdStop struct {
	Positional struct {
		ID string `positional-arg-name:"job-ID" required:"yes"`
	} `positional-args:"yes"`
}

type cmdStatus struct {
	Positional struct {
		ID string `positional-arg-name:"job-ID" required:"yes"`
	} `positional-args:"yes"`
}

type cmdOutput struct {
	Positional struct {
		ID string `positional-arg-name:"job-ID" required:"yes"`
	} `positional-args:"yes"`
}

type clientMixin struct {
	Address string `long:"address" description:"server address"`
	Cert    string `long:"cert" description:"client certificate"`
	Key     string `long:"key" description:"client key"`
	CACert  string `long:"CA"`
}

type options struct {
	clientMixin

	CmdStart  cmdStart  `command:"start"`
	CmdStop   cmdStop   `command:"stop"`
	CmdStatus cmdStatus `command:"status"`
	CmdOutput cmdOutput `command:"output"`
}

var (
	opts options
)

func main() {
	logrus.SetLevel(logrus.TraceLevel)
	_, err := flags.ParseArgs(&opts, os.Args[1:])
	if err != nil {
		if utils.IsErrHelp(err) {
			os.Exit(0)
		}
		os.Exit(1)
	}
}

func (c *clientMixin) client() (conn *grpc.ClientConn, client pb.JobPileManagerClient, err error) {
	cert, err := tls.LoadX509KeyPair(c.Cert, c.Key)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot load server certificate: %v", err)
	}

	caCertBytes, err := ioutil.ReadFile(c.CACert)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot read CA certificate: %v", err)
	}
	// very unlikely for the server cert of this demo to be signed by any
	// CAs from the system pool, but let's use it anyway
	pool, err := x509.SystemCertPool()
	if err != nil {
		return nil, nil, fmt.Errorf("cannot load system certificates pool: %v", err)
	}
	if !pool.AppendCertsFromPEM(caCertBytes) {
		return nil, nil, fmt.Errorf("cannot add CA certificate")
	}
	creds := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		// do our own verification instead
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			opts := x509.VerifyOptions{
				// ignore DNS name
				Intermediates: pool,
				Roots:         pool,
			}
			// TODO support intermediate certs
			serverCert := cs.PeerCertificates[0]
			logrus.Tracef("server: %v", serverCert.Subject)
			_, err := cs.PeerCertificates[0].Verify(opts)
			if err != nil {
				logrus.Tracef("verify err: %v", err)
				return err
			}
			// a trivial auth check
			isPilec := serverCert.Subject.CommonName == "piled"
			if !isPilec {
				return fmt.Errorf("expected a certificate of piled not %q", serverCert.Subject)
			}
			return nil
		},
	})
	conn, err = grpc.Dial(c.Address,
		grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, nil, fmt.Errorf("cannot connect: %w", err)
	}
	return conn, pb.NewJobPileManagerClient(conn), nil
}

func (c *cmdStart) Execute(args []string) error {
	fmt.Printf("start: %+v\n", c)
	conn, jm, err := opts.client()
	if err != nil {
		return fmt.Errorf("cannot connect: %w", err)
	}
	defer conn.Close()
	// TODO verify that args are indeed a valid command
	js := pb.JobStartRequest{
		Command: c.Positional.Args,
	}
	res, err := jm.Start(context.Background(), &js)
	if err != nil {
		return fmt.Errorf("cannot start job: %w", err)
	}
	if res.Error != "" {
		return fmt.Errorf("cannot start job: %v", res.Error)
	}
	fmt.Printf("job started with ID: %v\n", res.ID)
	return nil
}

func (c *cmdStop) Execute(args []string) error {
	fmt.Printf("stop: %+v\n", c)
	// TODO verify that job ID looks sane
	jobID := c.Positional.ID

	conn, jm, err := opts.client()
	if err != nil {
		return fmt.Errorf("cannot connect: %w", err)
	}
	defer conn.Close()
	jr := pb.JobRequest{
		ID: jobID,
	}
	res, err := jm.Stop(context.Background(), &jr)
	if err != nil {
		return fmt.Errorf("cannot stop job: %w", err)
	}
	if res.Error != "" {
		return fmt.Errorf("cannot stop job: %v", res.Error)
	}
	fmt.Printf("job %q stopped, status %v\n", jobID, res.Status)
	return nil
}

func (c *cmdStatus) Execute(args []string) error {
	jobID := c.Positional.ID

	conn, jm, err := opts.client()
	if err != nil {
		return fmt.Errorf("cannot connect: %w", err)
	}
	defer conn.Close()
	jr := pb.JobRequest{
		ID: jobID,
	}
	res, err := jm.Status(context.Background(), &jr)
	if err != nil {
		return fmt.Errorf("cannot query job status: %w", err)
	}
	fmt.Printf("job status: %+v\n", res)
	return nil
}

func (c *cmdOutput) Execute(args []string) error {
	jobID := c.Positional.ID

	conn, jm, err := opts.client()
	if err != nil {
		return fmt.Errorf("cannot connect: %w", err)
	}
	defer conn.Close()
	jr := pb.JobRequest{
		ID: jobID,
	}
	out, err := jm.Output(context.Background(), &jr)
	if err != nil {
		return fmt.Errorf("cannot obtain job output: %v", err)
	}
	for {
		chunk, err := out.Recv()
		if err != nil {
			return fmt.Errorf("cannot receive log chunk: %v", err)
		}
		fmt.Println(chunk.Chunk)
	}
	return nil
}
