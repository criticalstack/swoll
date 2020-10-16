// pretty dumb right now, uses docker-client environ defaults
package topology

import (
	"context"
	"log"

	"github.com/criticalstack/swoll/pkg/types"
	dockertypes "github.com/docker/docker/api/types"
	dockerfilt "github.com/docker/docker/api/types/filters"
	dockercli "github.com/docker/docker/client"
)

type DockerRuntime struct {
	client *dockercli.Client
}

func (d *DockerRuntime) Connect(ctx context.Context) error {
	if conn, err := dockercli.NewEnvClient(); err != nil {
		return err
	} else {
		d.client = conn
		return nil
	}
}

func (d *DockerRuntime) getPid(ctx context.Context, id string) (int, error) {
	req, err := d.client.ContainerInspect(ctx, id)
	if err != nil {
		return -1, err
	}

	return req.State.Pid, nil
}

func NewDockerRuntime() (*DockerRuntime, error) {
	return &DockerRuntime{}, nil
}

func (d *DockerRuntime) Containers(ctx context.Context, procroot string) ([]*types.Container, error) {
	if d.client == nil {
		if err := d.Connect(ctx); err != nil {
			return nil, err
		}
	}

	// filter only for running containers.
	filter := dockerfilt.NewArgs()
	filter.Add("status", "running")

	containers, err := d.client.ContainerList(ctx,
		dockertypes.ContainerListOptions{
			Filters: filter,
		})
	if err != nil {
		return nil, err
	}

	ret := make([]*types.Container, 0)
	for _, container := range containers {
		pid, err := d.getPid(ctx, container.ID)
		if err != nil {
			log.Printf("[warning] could not fetch pid for container '%s' (%v) ..skipping", container.ID, err)
			continue
		}

		pidns, err := getPidNamespace(procroot, pid)
		if err != nil {
			log.Printf("[warning] could not fetch pid-namespace for container '%s' (%v) .. skipping", container.ID, err)
			continue
		}

		ret = append(ret, &types.Container{
			ID:           container.ID,
			Labels:       container.Labels,
			Image:        container.Image,
			Name:         container.Names[0],
			Pid:          pid,
			PidNamespace: pidns,
		})

	}

	return ret, nil
}
