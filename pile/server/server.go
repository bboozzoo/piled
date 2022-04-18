package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	"github.com/bboozzoo/piled/pile/auth"
	pb "github.com/bboozzoo/piled/pile/proto"
	"github.com/bboozzoo/piled/runner"
)

type piled struct {
	pb.UnimplementedJobPileManagerServer
	runner Runner

	// dummy authorization which maps a token to a list of operations
	opAuthz map[string][]string
}

type Runner interface {
	Start(config runner.Config) (name string, err error)
	Stop(name string) (*runner.Status, error)
	Status(name string) (*runner.Status, error)
	Output(name string) (output <-chan []byte, cancel func(), err error)
}

// Start a job and return the result which contains the job ID.
func (p *piled) Start(_ context.Context, req *pb.JobStartRequest) (*pb.JobStartResult, error) {
	logrus.Tracef("start %+v", req)
	if err := p.opAuthorized(req.Token, "start"); err != nil {
		return nil, err
	}
	// TODO verify whether command is well formed
	config := runner.Config{
		Command: req.Command,
	}
	config.CPUMax = req.Resources.GetCPUMax()
	config.MemoryMax = req.Resources.GetMemoryMax()
	config.IOMax = req.Resources.GetIOMax()

	jobName, err := p.runner.Start(config)
	if err != nil {
		return nil, fmt.Errorf("cannot start job: %v", err)
	}
	return &pb.JobStartResult{
		ID: jobName,
	}, nil
}

func statusFromJobStatus(status *runner.Status) *pb.Status {
	s := &pb.Status{}
	switch {
	case status.Active:
		s.Status = pb.Status_ACTIVE
	case status.OOM:
		s.Status = pb.Status_OOM_KILLED
	case status.ExitStatus != 0:
		s.Status = pb.Status_FAILED
	default:
		s.Status = pb.Status_EXITED
	}
	s.ExitStatus = int32(status.ExitStatus)
	s.TermSignal = int32(status.Signal)
	return s
}

// Stop a given job.
func (p *piled) Stop(_ context.Context, req *pb.JobRequest) (*pb.StopResult, error) {
	logrus.Tracef("stop %+v", req)
	if err := p.opAuthorized(req.Token, "stop"); err != nil {
		return nil, err
	}
	status, err := p.runner.Stop(req.ID)
	if err != nil {
		return nil, fmt.Errorf("cannot stop job: %w", err)
	}
	// TODO clean job logs
	return &pb.StopResult{
		Status: statusFromJobStatus(status),
	}, nil
}

// Status obtains the status of a given job.
func (p *piled) Status(_ context.Context, req *pb.JobRequest) (*pb.StatusResult, error) {
	logrus.Tracef("status %+v", req)
	if err := p.opAuthorized(req.Token, "status"); err != nil {
		return nil, err
	}
	status, err := p.runner.Status(req.ID)
	if err != nil {
		return nil, fmt.Errorf("cannot obtain job status: %w", err)
	}
	return &pb.StatusResult{
		Status: statusFromJobStatus(status),
	}, nil
}

// Output obtains the output of a given job.
func (p *piled) Output(req *pb.JobRequest, out pb.JobPileManager_OutputServer) error {
	logrus.Tracef("output %+v", req)
	if err := p.opAuthorized(req.Token, "output"); err != nil {
		return err
	}
	output, cancel, err := p.runner.Output(req.ID)
	if err != nil {
		return fmt.Errorf("cannot start collecting job output: %w", err)
	}

	for {
		logrus.Tracef("waiting for logs")
		select {
		case chunk, ok := <-output:
			logrus.Tracef("got %vB of output", len(chunk))
			if !ok {
				logrus.Tracef("logs closed")
				return nil
			}
			if err := out.Send(&pb.OutputChunk{Chunk: chunk}); err != nil {
				logrus.Tracef("send failed: %v", err)
				cancel()
				return err
			}
		case <-out.Context().Done():
			logrus.Tracef("output context done")
			cancel()
			return out.Context().Err()
		}
	}
}

var NotAuthorizedError = fmt.Errorf("not authorized")

func (p *piled) opAuthorized(tok, op string) error {
	opsForToken, ok := p.opAuthz[tok]
	if !ok {
		// unknown token
		return NotAuthorizedError
	}
	i := sort.SearchStrings(opsForToken, op)
	if i < len(opsForToken) && opsForToken[i] == op {
		// op is allowed for token
		return nil
	}
	return NotAuthorizedError
}

func errToGrpcError(err error) error {
	if errors.Is(err, runner.JobNotFoundError) {
		return status.Errorf(codes.NotFound, "error: %v", err)
	}
	if errors.Is(err, NotAuthorizedError) {
		return status.Errorf(codes.PermissionDenied, "error: %v", err)
	}
	return err
}

func (p *piled) callIntercept(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
	// TODO grab peer and method and verify authorization
	resp, err = handler(ctx, req)
	logrus.Tracef("handler err: %v", err)
	return resp, errToGrpcError(err)
}

func (p *piled) streamIntercept(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	// TODO grab peer and method and verify authorization
	if err := handler(srv, ss); err != nil {
		logrus.Tracef("handler err: %v", err)
		return errToGrpcError(err)
	}
	return nil
}

// Serve makes the server implementation available on a given listener
func (p *PileServer) Serve(ctx context.Context, l net.Listener, authConfig auth.Config) error {
	creds := credentials.NewTLS(auth.ServerTLSConfig(authConfig))
	gsrv := grpc.NewServer(grpc.Creds(creds),
		grpc.UnaryInterceptor(p.pile.callIntercept),
		grpc.StreamInterceptor(p.pile.streamIntercept))
	pb.RegisterJobPileManagerServer(gsrv, &p.pile)

	go func() {
		<-ctx.Done()
		gsrv.GracefulStop()
	}()
	return gsrv.Serve(l)
}

type PileServer struct {
	pile piled
}

func NewWithRunner(runner Runner) *PileServer {
	allOps := []string{"start", "stop", "status", "output"}
	roOps := []string{"status", "output"}
	sort.Strings(allOps)
	sort.Strings(roOps)

	return &PileServer{
		pile: piled{
			runner: runner,

			opAuthz: map[string][]string{
				"admin-token": allOps,
				"ro-token":    roOps,
			},
		},
	}
}
