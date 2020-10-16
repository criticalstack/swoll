package topology

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/criticalstack/swoll/pkg/types"
	"google.golang.org/grpc"
	pb "k8s.io/cri-api/pkg/apis/runtime/v1alpha2"
)

// CRIRuntime encapsulates k8s CRI client stuff
type CRIRuntime struct {
	endpoint string           // fully-qualified path to the CRI socket
	client   *grpc.ClientConn // the CRI GRPC client context
}

// Connect will attempt to connect to the local CRI socket
func (c *CRIRuntime) Connect(ctx context.Context) error {
	conn, err := grpc.Dial(c.endpoint, grpc.WithInsecure(), grpc.WithContextDialer(
		func(ctx context.Context, addr string) (net.Conn, error) {
			return net.Dial("unix", c.endpoint)
		},
	))
	if err != nil {
		return err
	}

	c.client = conn
	return nil
}

// parse out the 'info' section of a container-status response
// in order to retrieve the process-id of the container in question.
// k8s-thought-leaders thought it would be a good idea to just stuff
// information in random places. So this hack deals with their hacks.
func (c *CRIRuntime) getPid(ctx context.Context, id string) (int, error) {
	rpcc := pb.NewRuntimeServiceClient(c.client)
	request := &pb.ContainerStatusRequest{ContainerId: id, Verbose: true}
	response, err := rpcc.ContainerStatus(ctx, request)

	if err != nil {
		return -1, err
	}

	rawinfo := response.GetInfo()
	info := make(map[string]interface{})

	if err := json.Unmarshal([]byte(rawinfo["info"]), &info); err != nil {
		return -1, err
	}

	if rawpid, ok := info["pid"]; ok {
		// all that for just this? KUBERNETES LOGIC!
		return int(rawpid.(float64)), nil
	}

	return -1, errors.New("no pid found in info response")
}

func (c *CRIRuntime) Close() error {
	if c.client != nil {
		return c.client.Close()
	}

	return nil
}

// Containers returns a list of containers in the RUNNING state from a CRI
// endpoint. procroot is the base-directory to the procfs, e.g., "/" for
// "/proc", or if you have an external procfs mount.
// Along with general container information, this also fetches the pid and
// pid-namespace of the running container.
func (c *CRIRuntime) Containers(ctx context.Context, procroot string) ([]*types.Container, error) {
	if c.client == nil {
		// attempt to connect to an unconnected context.
		if err := c.Connect(ctx); err != nil {
			return nil, err
		}
	}

	// we only care about containers that are marked as running
	request := &pb.ListContainersRequest{
		Filter: &pb.ContainerFilter{
			State: &pb.ContainerStateValue{
				State: pb.ContainerState_CONTAINER_RUNNING,
			},
		},
	}

	rpcc := pb.NewRuntimeServiceClient(c.client)
	// make the rpc request for the containers
	res, err := rpcc.ListContainers(ctx, request)
	if err != nil {
		return nil, err
	}

	containers := res.GetContainers()
	ret := make([]*types.Container, 0)

	for _, container := range containers {
		id := container.GetId()
		pid, err := c.getPid(ctx, id)
		if err != nil {
			// could not find a pid for this container, warn and skip since we
			// really can't do anything with this entry.
			log.Printf("[warning] could not fetch pid for container '%s' (%v) .. skipping", id, err)
			continue
		}

		pidns, err := getPidNamespace(procroot, pid)
		if err != nil {
			// could not fetch the pid-namespace of this container, warn and
			// continue.
			log.Printf("[warning] could not fetch pid-namespace for container '%s' (%v) .. skipping", id, err)
			continue
		}

		/*
			ctr := &types.Container{
				ID:           id,
				Labels:       container.GetLabels(),
				Image:        container.GetImageRef(),
				Pid:          pid,
				PidNamespace: pidns,
			}

				if name, ok := ctr.Labels["io.kubernetes.container.name"]; ok {
					ctr.Name = name
				}

				if pod, ok := ctr.Labels["io.kubernetes.pod.name"]; ok {
					ctr.Pod = pod
				}

				if k8ns, ok := ctr.Labels["io.kubernetes.pod.namespace"]; ok {
					ctr.Namespace = k8ns
				}
		*/

		ret = append(ret, &types.Container{
			ID:           id,
			Labels:       container.GetLabels(),
			Image:        container.GetImageRef(),
			Pid:          pid,
			PidNamespace: pidns,
		})

	}

	return ret, nil
}

func NewCRIRuntime(crisock string) (*CRIRuntime, error) {
	finfo, err := os.Stat(crisock)
	if err != nil {
		return nil, err
	}

	if finfo.Mode()&os.ModeSocket == 0 {
		return nil, fmt.Errorf("file '%s' is not a socket", crisock)
	}

	return &CRIRuntime{
		endpoint: crisock,
		client:   nil,
	}, nil
}
