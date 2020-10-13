package podmon

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path"
	"syscall"

	"google.golang.org/grpc"
	pb "k8s.io/cri-api/pkg/apis/runtime/v1alpha2"
)

type CRIEndpoint struct {
	protocol string
	address  string
	rpc      *grpc.ClientConn
}

// CRIContainer contains only the most relevant information for us
// from the running CRI.
type CRIContainer struct {
	id           string
	name         string
	pod          string
	namespace    string
	pidNamespace int
	utsNamespace int
	mntNamespace int
	pid          int
	labels       map[string]string
	ep           *CRIEndpoint
	raw          *pb.Container
}

func (c *CRIContainer) ID() (id string) {
	if c != nil {
		id = c.id
	}
	return
}

func (c *CRIContainer) Name() (name string) {
	if c != nil {
		name = c.name
	}
	return
}

func (c *CRIContainer) Pod() string {
	if c != nil {
		return c.pod
	}

	return ""
}

func (c *CRIContainer) Namespace() string {
	if c != nil {
		return c.namespace
	}

	return ""
}

func (c *CRIContainer) PodSandboxID() (id string) {
	if c != nil {
		id = c.raw.PodSandboxId
	}
	return
}

func (c *CRIContainer) Image() (image string) {
	if c != nil {
		image = c.raw.ImageRef
	}
	return
}

func (c *CRIContainer) GetLabels() (labels map[string]string) {
	if c != nil {
		labels = c.raw.Labels
	}
	return
}

func (c *CRIContainer) String() string {
	return fmt.Sprintf(
		"id=%v, name=%v, pod=%v, pidNS=%v, utsNS=%v, mntNS=%v, labels=%v",
		c.id, c.name, c.pod, c.pidNamespace, c.utsNamespace, c.mntNamespace, c.labels)
}

func (c *CRIContainer) Labels() map[string]string {
	if c != nil {
		return c.labels
	}

	return nil
}

func (c *CRIContainer) PIDNamespace() int {
	if c != nil {
		return c.pidNamespace
	}

	return -1
}

func (c *CRIContainer) UTSNamespace() int {
	if c != nil {
		return c.utsNamespace
	}

	return -1
}

func (c *CRIContainer) MNTNamespace() int {
	if c != nil {
		return c.mntNamespace
	}

	return -1
}

func parseCRIEndpoint(endpoint string) (string, string, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", "", err
	}

	switch u.Scheme {
	case "tcp":
		return u.Scheme, u.Host, nil
	case "unix":
		return u.Scheme, u.Path, nil
	}

	return "", "", fmt.Errorf("protocol %q not supported", u.Scheme)
}

// NewCRIEndpoint initializes the endpoint structure with the path to the CRI
// unix socket.
func NewCRIEndpoint(endpoint string) (*CRIEndpoint, error) {
	if endpoint == "" {
		return nil, fmt.Errorf("no CRI endpoint specified")
	}

	if endpoint[0] == '/' {
		endpoint = "unix://" + endpoint
	}

	proto, addr, err := parseCRIEndpoint(endpoint)
	if err != nil {
		return nil, err
	}

	if proto == "unix" {
		if _, err := os.Stat(addr); err != nil {
			return nil, err
		}
	}

	return &CRIEndpoint{
		protocol: proto,
		address:  addr,
	}, nil
}

// Connect will connect to the underlying cri endpoint's grpc iface.
func (cri *CRIEndpoint) Connect() error {
	if cri.rpc != nil {
		cri.rpc.Close()
	}

	conn, err := grpc.Dial(cri.address, grpc.WithInsecure(),
		grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
			return net.Dial(cri.protocol, cri.address)
		}))

	if err != nil {
		return err
	}

	cri.rpc = conn

	return nil
}

// GetContainers will fetch the currently running list of containers
// as seen by the CRI.
func (cri *CRIEndpoint) GetContainers(ctx context.Context, procRoot string) ([]*CRIContainer, error) {
	if cri.rpc == nil {
		if err := cri.Connect(); err != nil {
			return nil, err
		}
	}

	req := &pb.ListContainersRequest{
		Filter: &pb.ContainerFilter{
			State: &pb.ContainerStateValue{
				State: pb.ContainerState_CONTAINER_RUNNING,
			},
		},
	}

	client := pb.NewRuntimeServiceClient(cri.rpc)
	resp, err := client.ListContainers(ctx, req)
	if err != nil {
		return nil, err
	}

	ret := []*CRIContainer{}

	for _, container := range resp.GetContainers() {
		c := &CRIContainer{
			id:           container.GetId(),
			ep:           cri,
			raw:          container,
			pidNamespace: -1,
			pid:          -1,
		}

		c.labels = make(map[string]string)

		for k, v := range container.GetLabels() {
			c.labels[k] = v
		}

		if cname, ok := c.labels["io.kubernetes.container.name"]; ok {
			c.name = cname
		}

		if pod, ok := c.labels["io.kubernetes.pod.name"]; ok {
			c.pod = pod
		}

		if namespace, ok := c.labels["io.kubernetes.pod.namespace"]; ok {
			c.namespace = namespace
		}

		nfo, err := c.info()
		if err != nil {
			// XXX: deal with running containers with no aux info.
			// for now, we just skip insertion.
			continue
		}

		if kpid, ok := nfo["pid"]; ok {
			c.pid = int(kpid.(float64))

			if ns, err := getPidNamespace(procRoot, c.pid); err == nil {
				c.pidNamespace = ns
			}

			if ns, err := getUtsNamespace(procRoot, c.pid); err == nil {
				c.utsNamespace = ns
			}

			if ns, err := getMntNamespace(procRoot, c.pid); err == nil {
				c.mntNamespace = ns
			}

		} else {
			// XXX: deal with running containers with no pid namespace info.
			/// skip for now.
			continue
		}

		ret = append(ret, c)
	}

	return ret, nil
}

// info attempts to fetch the aux meta data from the CRI for a specific
// container. This includes various bits of data like the host, pid, etc.
func (c *CRIContainer) info() (map[string]interface{}, error) {
	if c.ep.rpc == nil {
		return nil, fmt.Errorf("cri endpoint not connected")
	}

	client := pb.NewRuntimeServiceClient(c.ep.rpc)

	req := &pb.ContainerStatusRequest{
		ContainerId: c.id,
		Verbose:     true,
	}

	resp, err := client.ContainerStatus(context.Background(), req)
	if err != nil {
		return nil, err
	}

	rawInfo := resp.GetInfo()
	info := make(map[string]interface{})

	if err := json.Unmarshal([]byte(rawInfo["info"]), &info); err != nil {
		return nil, err
	}

	return info, nil
}

// getNsIno will get the namespace of the pid.
func getNsIno(root string, pid int, t string) (int, error) {
	// when you stat -L pid_for_children, the actual inode number associated
	// with it will be the PID namespace of the running process. Neat eh?
	var stat syscall.Stat_t

	pfile := path.Join(root, "/proc", fmt.Sprintf("%d", pid), "ns", t)

	if err := syscall.Stat(pfile, &stat); err != nil {
		return -1, err
	}

	return int(stat.Ino), nil
}

func getUtsNamespace(root string, pid int) (int, error) {
	return getNsIno(root, pid, "uts")
}

func getPidNamespace(root string, pid int) (int, error) {
	return getNsIno(root, pid, "pid_for_children")
}

func getMntNamespace(root string, pid int) (int, error) {
	return getNsIno(root, pid, "mnt")
}
