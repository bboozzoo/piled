package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net"
	"net/url"
	"os"

	"github.com/jessevdk/go-flags"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	pb "github.com/bboozzoo/piled/pile/proto"
	"github.com/bboozzoo/piled/pile/server"
	"github.com/bboozzoo/piled/runner"
	"github.com/bboozzoo/piled/utils"
)

type options struct {
	Cert       string `long:"cert" description:"server certificate"`
	Key        string `long:"key" description:"server key"`
	CACert     string `long:"CA"`
	Positional struct {
		Address string `required:"yes" positional-arg-name:"ADDRESS" description:"listen address"`
	} `positional-args:"yes"`
}

func run(opt *options) error {
	addr := opt.Positional.Address
	// TODO veify that scheme is one of unix, tcp and so on
	u, err := url.Parse(addr)
	if err != nil {
		return fmt.Errorf("cannot use listen address %q: %v", addr, err)
	}
	logrus.Tracef("listen on %v:%v", u.Scheme, u.Port())

	cert, err := tls.LoadX509KeyPair(opt.Cert, opt.Key)
	if err != nil {
		return fmt.Errorf("cannot load server certificate: %v", err)
	}

	caCertBytes, err := ioutil.ReadFile(opt.CACert)
	if err != nil {
		return fmt.Errorf("cannot read CA certificate: %v", err)
	}
	// very unlikely for the client cert of this demo to be signed by any
	// CAs from the system pool, but let's use it anyway
	pool, err := x509.SystemCertPool()
	if err != nil {
		return fmt.Errorf("cannot load system certificates pool: %v", err)
	}
	if !pool.AppendCertsFromPEM(caCertBytes) {
		return fmt.Errorf("cannot add CA certificate")
	}

	creds := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
		ClientCAs:    pool,
		// do our own verification instead
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			opts := x509.VerifyOptions{
				Roots:     pool,
				KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			}
			// TODO support intermediate certs
			clientCert := cs.PeerCertificates[0]
			logrus.Tracef("client: %v", clientCert.Subject)
			_, err := clientCert.Verify(opts)
			if err != nil {
				logrus.Tracef("client cert verify err: %v", err)
				return err
			}
			// a trivial auth check
			isPilec := clientCert.Subject.CommonName == "pilec"
			if !isPilec {
				return fmt.Errorf("expected a certificate of pilec not %q", clientCert.Subject)
			}
			return nil
		},
	})
	gsrv := grpc.NewServer(grpc.Creds(creds))
	r, err := runner.NewCgroupRunner()
	if err != nil {
		return fmt.Errorf("cannot create runner: %v", err)
	}
	srv := server.NewWithRunner(r)
	pb.RegisterJobPileManagerServer(gsrv, srv)

	l, err := net.Listen(u.Scheme, ":"+u.Port())
	if err != nil {
		return fmt.Errorf("cannot listen on address %q: %w", addr, err)
	}
	if err := gsrv.Serve(l); err != nil {
		return fmt.Errorf("cannot serve grpc: %v", err)
	}
	return nil
}

func main() {
	logrus.SetLevel(logrus.TraceLevel)
	if runner.IsShimEntry() {
		shimEntry()
	}
	opt := &options{}
	_, err := flags.ParseArgs(opt, os.Args[1:])
	if err != nil {
		if utils.IsErrHelp(err) {
			os.Exit(0)
		}
		os.Exit(1)
	}
	if err := run(opt); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

func shimEntry() {
	err := runner.ShimEntry()
	fmt.Fprintf(os.Stderr, "cannot execute shim: %v\n", err)
	os.Exit(42)
}
