package types

import "fmt"

type Container struct {
	ID           string            `json:"id,omitempty"`
	Pod          string            `json:"pod,omitempty"`
	PodSandboxID string            `json:"sandbox-id,omitempty"`
	Name         string            `json:"name,omitempty"`
	Image        string            `json:"image,omitempty"`
	Namespace    string            `json:"namespace,omitempty"`
	Labels       map[string]string `json:"labels,omitempty"`
	Pid          int               `json:"pid,omitempty"`
	PidNamespace int               `json:"pid-namespace,omitempty"`
}

func (c *Container) FQDN() string {
	if c == nil {
		return "-.-.-"
	}

	return fmt.Sprintf("%s.%s.%s", c.Name, c.Pod, c.Namespace)
}
