package server

import (
	"context"
	"fmt"
	"strings"

	pb "github.com/bboozzoo/piled/pile/proto"
	"github.com/bboozzoo/piled/runner"
	"github.com/bboozzoo/piled/utils"

	"github.com/sirupsen/logrus"
)

type options struct {
	Positional struct {
		Address string `required:"yes" positional-arg-name:"ADDRESS" description:"listen address"`
	} `positional-args:"yes"`
}

type piled struct {
	pb.UnimplementedJobPileManagerServer
}

var errNotImplemented = fmt.Errorf("not implemented")

// Start a job and return the result which contains the job ID.
func (p *piled) Start(_ context.Context, req *pb.JobStartRequest) (*pb.JobStartResult, error) {
	logrus.Tracef("start %+v", req)
	uuid, err := utils.UUID()
	if err != nil {
		return nil, fmt.Errorf("cannot obtain UUID: %v", err)
	}
	// TODO verify whether command is well formed
	jobID := "pile." + uuid
	err = runner.StartJob("pile."+uuid, runner.Config{
		Command: req.Command,
	})
	if err != nil {
		return nil, fmt.Errorf("cannot start job: %v", err)
	}
	return &pb.JobStartResult{
		ID: jobID,
	}, nil
}

func validJobID(jobID string) bool {
	return strings.HasPrefix(jobID, "pile.")
}

// Stop a given job.
func (p *piled) Stop(_ context.Context, req *pb.JobRequest) (*pb.StopResult, error) {
	logrus.Tracef("stop %+v", req)

	if !validJobID(req.ID) {
		return nil, fmt.Errorf("cannot stop job with invalid id %q", req.ID)
	}
	if err := runner.StopJob(req.ID); err != nil {
		return nil, fmt.Errorf("cannot stop job: %v", err)
	}
	status, err := runner.JobStatus(req.ID)
	if err != nil {
		return nil, fmt.Errorf("cannot obtain job status: %v", err)
	}
	return &pb.StopResult{Status: int32(status.ExitStatus)}, nil
}

// Status obtains the status of a given job.
func (p *piled) Status(_ context.Context, req *pb.JobRequest) (*pb.StatusResult, error) {
	logrus.Tracef("status %+v", req)
	if !validJobID(req.ID) {
		return nil, fmt.Errorf("cannot stop job with invalid id %q", req.ID)
	}
	status, err := runner.JobStatus(req.ID)
	if err != nil {
		return nil, fmt.Errorf("cannot obtain job status: %v", err)
	}
	logrus.Tracef("status: %+v", status)
	return &pb.StatusResult{}, nil
}

// Output obtains the output of a given job.q
func (p *piled) Output(req *pb.JobRequest, _ pb.JobPileManager_OutputServer) error {
	logrus.Tracef("output %+v", req)
	if !validJobID(req.ID) {
		return fmt.Errorf("cannot stop job with invalid id %q", req.ID)
	}
	return errNotImplemented
}

func New() pb.JobPileManagerServer {
	return &piled{}
}
