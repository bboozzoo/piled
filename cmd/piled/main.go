package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"os"

	"github.com/jessevdk/go-flags"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"

	"github.com/bboozzoo/piled/pile/auth"
	"github.com/bboozzoo/piled/pile/server"
	"github.com/bboozzoo/piled/runner"
	"github.com/bboozzoo/piled/utils"
)

type options struct {
	Config     string `long:"config" description:"config file path"`
	Positional struct {
		ListenAddress string `positional-arg-name:"LISTEN-ADDRESS" description:"listen address"`
	} `positional-args:"yes"`
}

type config struct {
	Cert          string `yaml:"cert"`
	Key           string `yaml:"key"`
	CACert        string `yaml:"ca-cert"`
	ListenAddress string `yaml:"listen-address"`
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

var runnerNew = func(c *runner.RunnerConfig) (server.Runner, error) {
	return runner.NewCgroupRunner(c)
}

var netListen = net.Listen

func run(opt *options) error {
	conf, err := loadConfig(opt.Config)
	if err != nil {
		return fmt.Errorf("cannot load config: %v", err)
	}

	addr := conf.ListenAddress
	if opt.Positional.ListenAddress != "" {
		addr = opt.Positional.ListenAddress
	}
	if addr == "" {
		return fmt.Errorf("cannot run without an address")
	}
	// TODO veify that scheme is one of unix, tcp and so on
	u, err := url.Parse(addr)
	if err != nil {
		return fmt.Errorf("cannot use listen address %q: %v", addr, err)
	}
	logrus.Tracef("listen on %v:%v", u.Scheme, u.Port())

	cert, err := tls.LoadX509KeyPair(conf.Cert, conf.Key)
	if err != nil {
		return fmt.Errorf("cannot load server certificate: %v", err)
	}

	caCertBytes, err := os.ReadFile(conf.CACert)
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

	r, err := runnerNew(&runner.RunnerConfig{
		StorageRoot: "/tmp/piled/output",
		// so that jobs are named pile.<uuid>
		JobNamePrefix: "pile.",
	})
	if err != nil {
		return fmt.Errorf("cannot create runner: %v", err)
	}
	srv := server.NewWithRunner(r)

	l, err := netListen(u.Scheme, ":"+u.Port())
	if err != nil {
		return fmt.Errorf("cannot listen on address %q: %w", addr, err)
	}
	err = srv.Serve(context.TODO(), l, auth.Config{
		CAPool: pool,
		Cert:   cert,
	})
	if err != nil {
		return fmt.Errorf("cannot serve: %v", err)
	}
	return nil
}

func main() {
	if runner.IsShimEntry() {
		shimEntry()
	}
	logrus.SetLevel(logrus.TraceLevel)
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
