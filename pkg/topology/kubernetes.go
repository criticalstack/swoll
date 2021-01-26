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
	"net"
	"os"

	"github.com/criticalstack/swoll/pkg/types"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
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

// Kubernetes contains all the working parts to facilitate a Observer
// for kubernetes operation.
type Kubernetes struct {
	criSocket     string                // fully-qualified path to a CRI socket endpoint
	kubeConfig    string                // if running out-of-cluster, the kubeconfig file
	namespace     string                // only monitor events within a specific namespace
	labelSelector string                // labels to match on
	fieldSelector string                // fields to match on
	procRoot      string                // if your /proc is outside of root, (as in /mnt/other/proc)
	criClient     *grpc.ClientConn      // the CRI GRPC connection
	kubeClient    *kubernetes.Clientset // the kube rpc connection
	kubeWatcher   *kcache.ListWatch     // the listwatch client for monitoring pods
}

// WithKubernetesNamespace sets the namespace configuration option
func WithKubernetesNamespace(namespace string) KubernetesOption {
	return func(k *Kubernetes) error {
		k.namespace = namespace
		return nil
	}
}

// WithKubernetesProcRoot sets the root-directory to the "/proc" directory
func WithKubernetesProcRoot(path string) KubernetesOption {
	return func(k *Kubernetes) error {
		k.procRoot = path
		return nil
	}
}

// WithKubernetesCRI sets the cri file configuration option
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

// WithKubernetesConfig sets the path to the kube configuration file
func WithKubernetesConfig(kubeConfig string) KubernetesOption {
	return func(k *Kubernetes) error {
		k.kubeConfig = kubeConfig
		return nil
	}
}

// WithKubernetesLabelSelector sets the labelselector match configuration option
func WithKubernetesLabelSelector(l string) KubernetesOption {
	return func(k *Kubernetes) error {
		k.labelSelector = l
		return nil
	}
}

// WithKubernetesFieldSelector sets the fieldselector match configuration option
func WithKubernetesFieldSelector(f string) KubernetesOption {
	return func(k *Kubernetes) error {
		k.fieldSelector = f
		return nil
	}
}

// NewKubernetes creates a Observer object for watching kubernetes changes
func NewKubernetes(opts ...KubernetesOption) (*Kubernetes, error) {
	ret := &Kubernetes{namespace: kapi.NamespaceAll}

	for _, opt := range opts {
		if err := opt(ret); err != nil {
			return nil, err
		}
	}

	return ret, nil
}

// Copy copies all but the client connections from the parent.
func (k *Kubernetes) Copy(opts ...interface{}) (Observer, error) {
	kcopy := &Kubernetes{
		criSocket:     k.criSocket,
		kubeConfig:    k.kubeConfig,
		namespace:     k.namespace,
		labelSelector: k.labelSelector,
		fieldSelector: k.fieldSelector,
		procRoot:      k.procRoot,
	}

	for _, opt := range opts {
		optfn := opt.(KubernetesOption)
		if err := optfn(kcopy); err != nil {
			return nil, err
		}
	}

	return kcopy, nil
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

// Connect will do all the things to create client connects to both the
// kubernetes api, and the CRI grpc endpoint.
func (k *Kubernetes) Connect(ctx context.Context) error {
	if err := k.connectCRI(ctx); err != nil {
		return errors.Wrapf(err, "failed to connect to CRI endpoint '%s'", k.criSocket)
	}

	if err := k.connectKube(ctx); err != nil {
		return err
	}

	return nil
}

// getContainerPid takes a container-id and attempts to find the PID of the
// container using CRI from some of the meta-data found within the info section
// of the response.
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

// criContainers returns all running containers found in the CRI and attempts to
// resolve the pod, kube-namespace, and kernel-namespace.
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
				log.Warnf("no kubernets namespace/pod found in CRI labels")
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
			log.Warnf("could not fetch pid for container '%s' (%v) .. skipping", id, err)
			continue
		}

		pidns, err := getPidNamespace(k.procRoot, pid)
		if err != nil {
			// could not fetch the pid-namespace of this container, warn and
			// continue.
			log.Warnf("could not fetch pid-namespace for container '%s' (%v) .. skipping", id, err)
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

// Containers returns an array of running containers inside kubernetes.
func (k *Kubernetes) Containers(ctx context.Context) ([]*types.Container, error) {
	return k.criContainers(ctx)
}

// Close frees up all the running resources of this Kubernetes observer
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

// containersForPod returns a list of containers that match a pod.
func (k *Kubernetes) containersForPod(ctx context.Context, pod *kapi.Pod) []*types.Container {
	log.Tracef("attempting container lookup for pod=%s ns=%s\n", pod.Name, pod.Namespace)

	criContainers, err := k.criContainers(ctx, &matchPod{pod.Name, pod.Namespace})
	if err != nil {
		log.Warnf("failed to fetch CRI containers matching pod %s/%s: %v", pod.Name, pod.Namespace, err)
	}

	return criContainers
}

// Run connects to kube and watches for POD changes. When changes are seen,
// attempt to match the changes with the underlying CRI containers (to find the
// running PID of the container, and the underlying PID namespace).
func (k *Kubernetes) Run(ctx context.Context, out chan<- *ObservationEvent) {
	if k.kubeWatcher == nil {
		if err := k.connectKube(ctx); err != nil {
			log.Warnf("error connecting to kubernetes: %v", err)
			return
		}
	}

	phasedCache := make(map[string][]*types.Container)

	_, informer := kcache.NewInformer(k.kubeWatcher, &kapi.Pod{}, 0, kcache.ResourceEventHandlerFuncs{
		UpdateFunc: func(obj interface{}, newobj interface{}) {
			// We treat an update in two separate messages if the old status
			// does not equal the new status, and the new status is `Running`.
			oldpod := obj.(*kapi.Pod)
			newpod := newobj.(*kapi.Pod)

			log.Tracef("update: (name=%s) old.Phase=%v new.Phase=%v\n", newpod.Name, oldpod.Status.Phase, newpod.Status.Phase)

			if oldpod.Status.Phase == kapi.PodPending && newpod.Status.Phase == kapi.PodRunning {
				for _, c := range k.containersForPod(ctx, newpod) {
					log.Infof("adding %s.%s.%s\n", c.Name, c.Pod, c.Namespace)
					out <- &ObservationEvent{EventTypeStart, c}
				}
			}

			if oldpod.Status.Phase == kapi.PodRunning && newpod.Status.Phase == kapi.PodRunning {
				// We need to inform any callers of this function that a pod,
				// and all of its underlying containers have been removed.
				// Problem is: by the time the `DeleteFunc` callback is called,
				// we are unable to obtain the kernel namespaces for the
				// containers from the CRI, since well, they have already been
				// shut down.
				//
				// If a POD is being deleted, the first phase of removal will
				// call the UpdateFunc callback with both the old and new phases
				// set as Running. So when we see an update with both old and
				// new status.phase=Running, we update a small cache for future
				// DeleteFunc calls to fetch the containers that WERE running
				// (though a bit stale).
				key := newpod.Name + "." + newpod.Namespace

				if _, ok := phasedCache[key]; !ok {
					ctrs := k.containersForPod(ctx, newpod)
					if len(ctrs) > 0 {
						log.Tracef("no phase transition, caching containers for pod %s (potential purge)\n", key)
						phasedCache[key] = ctrs
					}
				}
			}

		},
		DeleteFunc: func(obj interface{}) {
			log.Traceln("remove: ", obj.(*kapi.Pod).Name)
			key := obj.(*kapi.Pod).Name + "." + obj.(*kapi.Pod).Namespace

			var containers []*types.Container

			if ctrs, ok := phasedCache[key]; ok {
				// Hopefully the UpdateFunc callback was executed for this
				// removal BEFORE this callback was executed. Reason being is,
				// if we are at the final stage of a Pod removal, we will not be
				// able to obtain kernel-namespace values for the underlying
				// containers (as they have been evicted from the system).
				containers = ctrs
				// remove this from the phaseCache
				delete(phasedCache, key)
			} else {
				// Hopefully we never actually get here as the containers will
				// probably be gone from the system by the time we look.
				containers = k.containersForPod(ctx, obj.(*kapi.Pod))
			}

			for _, c := range containers {
				log.Infof("removing %s.%s.%s\n", c.Name, c.Pod, c.Namespace)
				out <- &ObservationEvent{EventTypeStop, c}
			}
		},
		AddFunc: func(obj interface{}) {
			log.Traceln("add: ", obj.(*kapi.Pod).Name)

			for _, c := range k.containersForPod(ctx, obj.(*kapi.Pod)) {
				log.Infof("adding %s.%s.%s\n", c.Name, c.Pod, c.Namespace)
				out <- &ObservationEvent{EventTypeStart, c}
			}

		},
	})

	informer.Run(ctx.Done())
}
