package server

import (
	"context"

	pb "github.com/bboozzoo/piled/pile/proto"
)

type GRPCServer interface {
	Start(_ context.Context, req *pb.JobStartRequest) (*pb.JobStartResult, error)
	Stop(_ context.Context, req *pb.JobRequest) (*pb.StopResult, error)
	Status(_ context.Context, req *pb.JobRequest) (*pb.StatusResult, error)
	Output(req *pb.JobRequest, out pb.JobPileManager_OutputServer) error
}

func (p *PileServer) Server() GRPCServer {
	return &p.pile
}

func (p *PileServer) OpAuthorized(tok, opt string) error {
	return p.pile.opAuthorized(tok, opt)
}
