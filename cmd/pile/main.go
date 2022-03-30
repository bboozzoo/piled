package main

import (
	"context"
	"fmt"
	"os"

	pb "github.com/bboozzoo/piled/pile/proto"
	"github.com/bboozzoo/piled/utils"

	"github.com/jessevdk/go-flags"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type cmdStart struct {
	clientMixin
	MemoryMax uint64 `long:"memory-max" description:"Max memory for this job"`
	CPUWeight uint   `long:"cpu-weight" description:"CPU weight of this job"`
	IOWeight  uint   `long:"io-weight" description:"IO weight of this job"`

	Positional struct {
		Args []string `positional-arg-name:"arg" required:"1"`
	} `positional-args:"yes"`
}

type cmdStop struct {
	clientMixin
	Positional struct {
		ID string `positional-arg-name:"job-ID" required:"yes"`
	} `positional-args:"yes"`
}

type cmdStatus struct {
	clientMixin

	Positional struct {
		ID string `positional-arg-name:"job-ID" required:"yes"`
	} `positional-args:"yes"`
}

type cmdOutput struct {
	clientMixin

	Positional struct {
		ID string `positional-arg-name:"job-ID" required:"yes"`
	} `positional-args:"yes"`
}

type clientMixin struct {
	Address string `long:"address" description:"server address"`
}

type options struct {
	CmdStart  cmdStart  `command:"start"`
	CmdStop   cmdStop   `command:"stop"`
	CmdStatus cmdStatus `command:"status"`
	CmdOutput cmdOutput `command:"output"`
}

func main() {
	_, err := flags.ParseArgs(&options{}, os.Args[1:])
	if err != nil {
		if utils.IsErrHelp(err) {
			os.Exit(0)
		}
		os.Exit(1)
	}
}

func (c *clientMixin) client() (conn *grpc.ClientConn, client pb.JobPileManagerClient, err error) {
	conn, err = grpc.Dial(c.Address,
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, nil, fmt.Errorf("cannot connect: %w", err)
	}
	return conn, pb.NewJobPileManagerClient(conn), nil
}

func (c *cmdStart) Execute(args []string) error {
	fmt.Printf("start: %+v\n", c)
	conn, jm, err := c.client()
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

	conn, jm, err := c.client()
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

	conn, jm, err := c.client()
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

	conn, jm, err := c.client()
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
