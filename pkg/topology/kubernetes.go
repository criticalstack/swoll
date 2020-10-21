// In order to properly satisfy the topology interface, the kubernetes wrapper
// will monitor POD events (either starting, updating, or stopping) and match
// them with information from the underlying CRI (Container Runtime Interface)
// which is managed by the kubelet.
//
// We utilize the CRI endpoints to fetch the current PID, and PID namespace
// associated with every container in a POD. When any POD event is seen, this
// code will automatically scan the CRI for containers that match these PODS.
package topology

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/criticalstack/swoll/pkg/types"
	"github.com/pkg/errors"
	"google.golang.org/grpc"
	kapi "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	klient "k8s.io/client-go/rest"
	kcache "k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
	pb "k8s.io/cri-api/pkg/apis/runtime/v1alpha2"

	"k8s.io/client-go/kubernetes"
)

type KubernetesOption func(*Kubernetes) error

type Kubernetes struct {
	criSocket     string
	kubeConfig    string
	namespace     string
	labelSelector string
	fieldSelector string
	procRoot      string
	criClient     *grpc.ClientConn
	kubeClient    *kubernetes.Clientset
	kubeWatcher   *kcache.ListWatch
}

func WithKubernetesNamespace(namespace string) KubernetesOption {
	return func(k *Kubernetes) error {
		k.namespace = namespace
		return nil
	}
}

func WithKubernetesProcRoot(path string) KubernetesOption {
	return func(k *Kubernetes) error {
		k.procRoot = path
		return nil
	}
}

func WithKubernetesCRI(criSocket string) KubernetesOption {
	return func(k *Kubernetes) error {
		sinfo, err := os.Stat(criSocket)
		if err != nil {
			return err
		}

		if sinfo.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("crisocket '%s' is not a unix socket", criSocket)
		}

		k.criSocket = criSocket
		return nil
	}
}

func WithKubernetesConfig(kubeConfig string) KubernetesOption {
	return func(k *Kubernetes) error {
		k.kubeConfig = kubeConfig
		return nil
	}
}

func WithKubernetesLabelSelector(l string) KubernetesOption {
	return func(k *Kubernetes) error {
		k.labelSelector = l
		return nil
	}
}
func WithKubernetesFieldSelector(f string) KubernetesOption {
	return func(k *Kubernetes) error {
		k.fieldSelector = f
		return nil
	}
}

func NewKubernetes(opts ...KubernetesOption) (*Kubernetes, error) {
	ret := &Kubernetes{namespace: kapi.NamespaceAll}

	for _, opt := range opts {
		if err := opt(ret); err != nil {
			return nil, err
		}
	}

	return ret, nil
}

func (k *Kubernetes) connectCRI(ctx context.Context) error {
	conn, err := grpc.Dial(k.criSocket, grpc.WithInsecure(), grpc.WithContextDialer(
		func(ctx context.Context, addr string) (net.Conn, error) {
			return net.Dial("unix", k.criSocket)
		},
	))
	if err != nil {
		return err
	}

	k.criClient = conn
	return nil
}

func (k *Kubernetes) connectKube(ctx context.Context) error {
	var (
		kclicfg *klient.Config
		err     error
	)

	if k.kubeConfig == "" {
		kclicfg, err = klient.InClusterConfig()
	} else {
		kclicfg, err = clientcmd.BuildConfigFromFlags("", k.kubeConfig)
	}
	if err != nil {
		return errors.Wrapf(err, "bad kube-config directive '%s'", k.kubeConfig)
	}

	if client, err := kubernetes.NewForConfig(kclicfg); err != nil {
		return err
	} else {
		k.kubeClient = client
	}

	optionsModifier := func(options *metav1.ListOptions) {
		if k.labelSelector != "" {
			options.LabelSelector = k.labelSelector
		}

		if k.fieldSelector != "" {
			options.FieldSelector = k.fieldSelector
		}
	}

	k.kubeWatcher = kcache.NewFilteredListWatchFromClient(
		k.kubeClient.CoreV1().RESTClient(),
		"pods",
		k.namespace,
		optionsModifier)

	return nil

}

func (k *Kubernetes) Connect(ctx context.Context) error {
	if err := k.connectCRI(ctx); err != nil {
		return errors.Wrapf(err, "failed to connect to CRI endpoint '%s'", k.criSocket)
	}

	if err := k.connectKube(ctx); err != nil {
		return err
	}

	return nil
}

func (k *Kubernetes) getContainerPid(ctx context.Context, id string) (int, error) {
	rpc := pb.NewRuntimeServiceClient(k.criClient)
	request := &pb.ContainerStatusRequest{ContainerId: id, Verbose: true}
	response, err := rpc.ContainerStatus(ctx, request)

	if err != nil {
		return -1, err
	}

	rawinfo := response.GetInfo()
	info := make(map[string]interface{})

	if err := json.Unmarshal([]byte(rawinfo["info"]), &info); err != nil {
		return -1, err
	}

	if rawpid, ok := info["pid"]; ok {
		return int(rawpid.(float64)), nil
	}

	return -1, errors.New("no pid found in info response")
}

type matchPod struct {
	podName      string
	podNamespace string
}

func (k *Kubernetes) criContainers(ctx context.Context, match ...*matchPod) ([]*types.Container, error) {
	if k.criClient == nil {
		if err := k.connectCRI(ctx); err != nil {
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

	rpc := pb.NewRuntimeServiceClient(k.criClient)
	// make the rpc request for the containers
	res, err := rpc.ListContainers(ctx, request)
	if err != nil {
		return nil, err
	}

	containers := res.GetContainers()
	ret := make([]*types.Container, 0)

	for _, container := range containers {
		labels := container.GetLabels()

		// we use the following attribute labels to associate cri info to the
		// corresponding kube host.
		pod := labels["io.kubernetes.pod.name"]
		kns := labels["io.kubernetes.pod.namespace"]
		name := labels["io.kubernetes.container.name"]

		// if we have the optional match argument, only continue if this
		// container matches.
		if len(match) > 0 {
			if pod == "" || kns == "" {
				log.Printf("[warning] no kubernets namespace/pod found in CRI labels")
				continue
			}

			m := match[0]

			if m.podName != pod || m.podNamespace != kns {
				// this CRI container did not match the optional match argument,
				// so skip insertion into our final result.
				continue
			}
		}

		id := container.GetId()
		pid, err := k.getContainerPid(ctx, id)
		if err != nil {
			// could not find a pid for this container, warn and skip since we
			// really can't do anything with this entry.
			log.Printf("[warning] could not fetch pid for container '%s' (%v) .. skipping", id, err)
			continue
		}

		pidns, err := getPidNamespace(k.procRoot, pid)
		if err != nil {
			// could not fetch the pid-namespace of this container, warn and
			// continue.
			log.Printf("[warning] could not fetch pid-namespace for container '%s' (%v) .. skipping", id, err)
			continue
		}

		ret = append(ret, &types.Container{
			ID:           id,
			Labels:       labels,
			Image:        container.GetImageRef(),
			Pod:          pod,
			Namespace:    kns,
			Name:         name,
			Pid:          pid,
			PidNamespace: pidns})

	}

	return ret, nil
}

func (k *Kubernetes) Containers(ctx context.Context) ([]*types.Container, error) {
	return k.criContainers(ctx)
}

func (k *Kubernetes) Close() error {
	if k != nil {
		if k.criClient != nil {
			if err := k.criClient.Close(); err != nil {
				return err
			}
		}
	}

	return nil
}

func (k *Kubernetes) containersForPod(ctx context.Context, pod *kapi.Pod) []*types.Container {
	criContainers, err := k.criContainers(ctx, &matchPod{pod.Name, pod.Namespace})
	if err != nil {
		log.Printf("[warning] failed to fetch CRI containers matching pod %s/%s: %v", pod.Name, pod.Namespace, err)
	}

	return criContainers
}

func (k *Kubernetes) Run(ctx context.Context, out chan<- *ObservationEvent) error {
	if k.kubeWatcher == nil {
		if err := k.connectKube(ctx); err != nil {
			return err
		}
	}

	_, informer := kcache.NewInformer(k.kubeWatcher, &kapi.Pod{}, 0, kcache.ResourceEventHandlerFuncs{
		UpdateFunc: func(obj interface{}, newobj interface{}) {
			oldpod := obj.(*kapi.Pod)
			newpod := newobj.(*kapi.Pod)

			for _, c := range k.containersForPod(ctx, oldpod) {
				log.Printf("[info] removing %s.%s.%s\n", c.Name, c.Pod, c.Namespace)

				out <- &ObservationEvent{EventTypeStop, c}
			}

			if oldpod.Status.Phase != newpod.Status.Phase {
				if newpod.Status.Phase == kapi.PodRunning {
					for _, c := range k.containersForPod(ctx, newpod) {
						log.Printf("[info] adding %s.%s.%s\n", c.Name, c.Pod, c.Namespace)

						out <- &ObservationEvent{EventTypeStart, c}
					}
				}
			}
		},
		DeleteFunc: func(obj interface{}) {
			for _, c := range k.containersForPod(ctx, obj.(*kapi.Pod)) {
				log.Printf("[info] removing %s.%s.%s\n", c.Name, c.Pod, c.Namespace)

				out <- &ObservationEvent{EventTypeStop, c}
			}
		},
		AddFunc: func(obj interface{}) {
			for _, c := range k.containersForPod(ctx, obj.(*kapi.Pod)) {
				log.Printf("[info] adding %s.%s.%s\n", c.Name, c.Pod, c.Namespace)

				out <- &ObservationEvent{EventTypeStart, c}
			}

		},
	})

	informer.Run(ctx.Done())

	return nil
}
