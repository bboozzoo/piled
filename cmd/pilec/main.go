package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"os"

	"github.com/jessevdk/go-flags"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"gopkg.in/yaml.v3"

	"github.com/bboozzoo/piled/pile/auth"
	pb "github.com/bboozzoo/piled/pile/proto"
	"github.com/bboozzoo/piled/utils"
)

type config struct {
	Cert    string `yaml:"cert"`
	Key     string `yaml:"key"`
	CACert  string `yaml:"ca-cert"`
	Address string `yaml:"address"`
	Token   string `yaml:"token"`
}

type cmdStart struct {
	MemoryMax string `long:"memory-max" description:"Max memory for this job"`
	CPUMax    string `long:"cpu-max" description:"Max CPU of this job"`
	IOMax     string `long:"io-max" description:"Max IO of this job"`

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

type commonMixin struct {
	Config  string `long:"config" description:"config file path" required:"yes"`
	Address string `long:"address" description:"server address"`
	Token   string `long:"token" description:"authorization token"`
	Debug   bool   `long:"debug"`
}

type options struct {
	commonMixin

	CmdStart  cmdStart  `command:"start"`
	CmdStop   cmdStop   `command:"stop"`
	CmdStatus cmdStatus `command:"status"`
	CmdOutput cmdOutput `command:"output"`
}

var (
	opts   options
	stdout io.Writer = os.Stdout
)

func parser() *flags.Parser {
	p := flags.NewParser(&opts, flags.Default)
	p.CommandHandler = func(command flags.Commander, args []string) error {
		if opts.Debug {
			logrus.SetLevel(logrus.TraceLevel)
		}
		return command.Execute(args)
	}
	return p
}

func main() {
	p := parser()
	_, err := p.ParseArgs(os.Args[1:])
	if err != nil {
		if utils.IsErrHelp(err) {
			os.Exit(0)
		}
		os.Exit(1)
	}
}

func loadConfig(from string) (*config, error) {
	f, err := os.Open(from)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	d := yaml.NewDecoder(f)
	var c config
	if err := d.Decode(&c); err != nil {
		return nil, err
	}
	logrus.Tracef("config: %+v", c)
	if c.CACert == "" || c.Cert == "" || c.Key == "" {
		return nil, fmt.Errorf("missing CA, certificate or key")
	}
	// fixup paths if not absolute
	c.CACert = utils.FixupPathIfRelative(c.CACert, from)
	c.Cert = utils.FixupPathIfRelative(c.Cert, from)
	c.Key = utils.FixupPathIfRelative(c.Key, from)
	return &c, nil
}

func (c *commonMixin) client() (conn *grpc.ClientConn, client pb.JobPileManagerClient, token string, err error) {
	conf, err := loadConfig(c.Config)
	if err != nil {
		return nil, nil, "", fmt.Errorf("cannot load config: %v", err)
	}
	addr := conf.Address
	if c.Address != "" {
		addr = c.Address
	}
	if addr == "" {
		return nil, nil, "", fmt.Errorf("cannot create client without an address")
	}
	token = conf.Token
	if c.Token != "" {
		token = c.Token
	}
	if token == "" {
		return nil, nil, "", fmt.Errorf("cannot perform requests without a token")
	}

	cert, err := tls.LoadX509KeyPair(conf.Cert, conf.Key)
	if err != nil {
		return nil, nil, "", fmt.Errorf("cannot load server certificate: %v", err)
	}

	caCertBytes, err := os.ReadFile(conf.CACert)
	if err != nil {
		return nil, nil, "", fmt.Errorf("cannot read CA certificate: %v", err)
	}
	// very unlikely for the server cert of this demo to be signed by any
	// CAs from the system pool, but let's use it anyway
	pool, err := x509.SystemCertPool()
	if err != nil {
		return nil, nil, "", fmt.Errorf("cannot load system certificates pool: %v", err)
	}
	if !pool.AppendCertsFromPEM(caCertBytes) {
		return nil, nil, "", fmt.Errorf("cannot add CA certificate")
	}
	creds := credentials.NewTLS(auth.ClientTLSConfig(auth.Config{
		CAPool: pool,
		Cert:   cert,
	}))
	conn, err = grpc.Dial(addr,
		grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, nil, "", fmt.Errorf("cannot connect: %w", err)
	}
	return conn, pb.NewJobPileManagerClient(conn), token, nil
}

func (c *cmdStart) Execute(args []string) error {
	logrus.Tracef("start: %+v\n", c)
	conn, jm, token, err := opts.client()
	if err != nil {
		return fmt.Errorf("cannot connect: %w", err)
	}
	defer conn.Close()
	// TODO verify that args are indeed a valid command
	js := pb.JobStartRequest{
		Token: token,
		Resources: &pb.Resources{
			CPUMax:    c.CPUMax,
			MemoryMax: c.MemoryMax,
			IOMax:     c.IOMax,
		},
		Command: c.Positional.Args,
	}
	res, err := jm.Start(context.Background(), &js)
	if err != nil {
		return fmt.Errorf("cannot start job: %w", err)
	}
	fmt.Fprintln(stdout, res.ID)
	return nil
}

func (c *cmdStop) Execute(args []string) error {
	logrus.Tracef("stop: %+v\n", c)
	// TODO verify that job ID looks sane
	jobID := c.Positional.ID

	conn, jm, token, err := opts.client()
	if err != nil {
		return fmt.Errorf("cannot connect: %w", err)
	}
	defer conn.Close()
	jr := pb.JobRequest{
		Token: token,
		ID:    jobID,
	}
	res, err := jm.Stop(context.Background(), &jr)
	if err != nil {
		return fmt.Errorf("cannot stop job: %w", err)
	}
	return printStatus(stdout, res.Status)
}

func printStatus(w io.Writer, status *pb.Status) error {
	b := &bytes.Buffer{}
	switch status.Status {
	case pb.Status_ACTIVE:
		b.WriteString("active")
	case pb.Status_FAILED, pb.Status_OOM_KILLED:
		label := "failed"
		if status.Status == pb.Status_OOM_KILLED {
			label = "oom-kill"
		}
		fmt.Fprintf(b, "%s (status=%v", label, status.ExitStatus)
		if status.TermSignal != 0 {
			fmt.Fprintf(b, ",signal=%v", status.TermSignal)
		}
		b.WriteRune(')')
	case pb.Status_EXITED:
		b.WriteString("exited")
	default:
		fmt.Fprintf(b, "<unknown %v>", status.Status)
	}
	b.WriteRune('\n')
	_, err := w.Write(b.Bytes())
	return err
}

func (c *cmdStatus) Execute(args []string) error {
	jobID := c.Positional.ID

	conn, jm, token, err := opts.client()
	if err != nil {
		return fmt.Errorf("cannot connect: %w", err)
	}
	defer conn.Close()
	jr := pb.JobRequest{
		Token: token,
		ID:    jobID,
	}
	res, err := jm.Status(context.Background(), &jr)
	if err != nil {
		return fmt.Errorf("cannot query job status: %w", err)
	}
	return printStatus(stdout, res.Status)
}

func (c *cmdOutput) Execute(args []string) error {
	jobID := c.Positional.ID

	conn, jm, token, err := opts.client()
	if err != nil {
		return fmt.Errorf("cannot connect: %w", err)
	}
	defer conn.Close()
	jr := pb.JobRequest{
		Token: token,
		ID:    jobID,
	}
	out, err := jm.Output(context.Background(), &jr)
	if err != nil {
		return fmt.Errorf("cannot obtain job output: %v", err)
	}
	for {
		chunk, err := out.Recv()
		if err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("cannot receive log chunk: %v", err)
		}
		stdout.Write(chunk.Chunk)
	}
	return nil
}
