package main

import (
	"fmt"
	"net"
	"net/url"
	"os"

	pb "github.com/bboozzoo/piled/pile/proto"
	"github.com/bboozzoo/piled/pile/server"
	"github.com/bboozzoo/piled/utils"

	"github.com/jessevdk/go-flags"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

type options struct {
	Positional struct {
		Address string `required:"yes" positional-arg-name:"ADDRESS" description:"listen address"`
	} `positional-args:"yes"`
}

func run(opt *options) error {
	addr := opt.Positional.Address
	u, err := url.Parse(addr)
	if err != nil {
		return fmt.Errorf("cannot use listen address %q: %v", addr, err)
	}
	logrus.Tracef("listen on %v:%v", u.Scheme, u.Port())
	// TODO veify that scheme is one of unix, tcp and so on
	l, err := net.Listen(u.Scheme, ":"+u.Port())
	if err != nil {
		return fmt.Errorf("cannot listen on address %q: %w", addr, err)
	}

	gsrv := grpc.NewServer()
	pb.RegisterJobPileManagerServer(gsrv, server.New())
	if err := gsrv.Serve(l); err != nil {
		return fmt.Errorf("cannot serve grpc: %v", err)
	}
	return nil
}

func main() {
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
