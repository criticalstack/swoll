package topology_test

import (
	"fmt"

	"github.com/criticalstack/swoll/pkg/topology"
)

func ExampleNewKubernetes() {
	observer, err := topology.NewKubernetes(
		topology.WithKubernetesConfig("/root/.kube/config"),
		topology.WithKubernetesNamespace("kube-system"),
		topology.WithKubernetesCRI("/run/containerd/containerd.sock"),
		topology.WithKubernetesLabelSelector("app=nginx"),
		topology.WithKubernetesFieldSelector("status.phase=Running"))
	if err != nil {
		panic(err)
	}

	fmt.Println(observer)
}
