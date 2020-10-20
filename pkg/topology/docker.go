package topology

import (
	dockercli "github.com/docker/docker/client"
)

type DockerOption func(*Docker) error

type Docker struct {
	client *dockercli.Client
}
