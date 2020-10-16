package topology

import (
	"context"
	"fmt"
	"log"

	"github.com/criticalstack/swoll/pkg/types"
	"github.com/pkg/errors"
	kapi "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	kclient "k8s.io/client-go/rest"
	kcache "k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
)

type KubeOption func(*KubeWatcher)

type KubeWatcher struct {
	namespace     string
	labelSelector string
	fieldSelector string
	configFile    string
	clientConfig  *kclient.Config
	client        *kubernetes.Clientset
	watcher       *kcache.ListWatch
}

func WithKubeConfig(kubeconf string) KubeOption {
	return func(k *KubeWatcher) {
		k.configFile = kubeconf
	}
}

func WithKubeNamespace(ns string) KubeOption {
	return func(k *KubeWatcher) {
		if ns == "" {
			ns = kapi.NamespaceAll
		}

		k.namespace = ns
	}
}

func WithKubeLabelSelector(label string) KubeOption {
	return func(k *KubeWatcher) {
		k.labelSelector = label
	}
}

func WithKubeFieldSelector(field string) KubeOption {
	return func(k *KubeWatcher) {
		k.fieldSelector = field
	}
}

func NewKubeWatcher(opts ...KubeOption) *KubeWatcher {
	ret := &KubeWatcher{namespace: kapi.NamespaceAll}

	for _, opt := range opts {
		opt(ret)
	}

	return ret
}

func (k *KubeWatcher) Connect(ctx context.Context) error {
	var err error

	if k.configFile == "" {
		log.Println("[info] using in-cluster configuration")
		k.clientConfig, err = kclient.InClusterConfig()
	} else {
		log.Println("[info] using out-of-cluster configuration")
		k.clientConfig, err = clientcmd.BuildConfigFromFlags("", k.configFile)
	}
	if err != nil {
		return errors.Wrapf(err, "bad configuration directive '%s'", k.configFile)
	}

	if rpcc, err := kubernetes.NewForConfig(k.clientConfig); err != nil {
		return err
	} else {
		k.client = rpcc
	}

	optionsModifier := func(options *metav1.ListOptions) {
		if k.labelSelector != "" {
			options.LabelSelector = k.labelSelector
		}

		if k.fieldSelector != "" {
			options.FieldSelector = k.fieldSelector
		}
	}

	k.watcher = kcache.NewFilteredListWatchFromClient(
		k.client.CoreV1().RESTClient(),
		"pods",
		k.namespace,
		optionsModifier,
	)

	return nil
}

// containersFromPod generates a list of `types.Container` formatted structures from a
// kubernetes api.Pod's container-status object.
func (k *KubeWatcher) containersFromPod(pod *kapi.Pod) []*types.Container {
	ret := make([]*types.Container, 0)
	for _, container := range pod.Status.ContainerStatuses {
		ret = append(ret, &types.Container{
			ID:        container.ContainerID,
			Pod:       pod.Name,
			Name:      container.Name,
			Image:     container.Image,
			Namespace: pod.Namespace,
		})
	}

	return ret
}

func (k *KubeWatcher) Run(ctx context.Context, out chan<- *WatchEvent) error {
	_, informer := kcache.NewInformer(k.watcher, &kapi.Pod{}, 0, kcache.ResourceEventHandlerFuncs{
		UpdateFunc: func(obj interface{}, newobj interface{}) {
			oldpod := obj.(*kapi.Pod)
			newpod := newobj.(*kapi.Pod)

			for _, c := range k.containersFromPod(oldpod) {
				log.Printf("[info] removing %s.%s.%s\n", c.Name, c.Pod, c.Namespace)

				out <- &WatchEvent{WatchEventDown, c}
			}

			if oldpod.Status.Phase != newpod.Status.Phase {
				if newpod.Status.Phase == kapi.PodRunning {
					for _, c := range k.containersFromPod(newpod) {
						fmt.Printf("[info] adding %s.%s.%s\n", c.Name, c.Pod, c.Namespace)

						out <- &WatchEvent{WatchEventUp, c}
					}
				}
			}
		},
		DeleteFunc: func(obj interface{}) {
			for _, c := range k.containersFromPod(obj.(*kapi.Pod)) {
				log.Printf("[info] removing %s.%s.%s\n", c.Name, c.Pod, c.Namespace)

				out <- &WatchEvent{WatchEventDown, c}
			}
		},
		AddFunc: func(obj interface{}) {
			for _, c := range k.containersFromPod(obj.(*kapi.Pod)) {
				log.Printf("[info] adding %s.%s.%s\n", c.Name, c.Pod, c.Namespace)

				out <- &WatchEvent{WatchEventUp, c}
			}

		},
	})

	informer.Run(ctx.Done())
	return nil
}
