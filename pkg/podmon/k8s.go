package podmon

import (
	"context"
	"fmt"
	"log"

	api "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	kclient "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	PODEventTypeAdd = 1
	PODEventTypeDel = 2
	PODEventTypeUpd = 3
)

type K8SEndpoint struct {
	config *kclient.Config
	rpc    *kubernetes.Clientset
}

type K8SPODEventType int

type K8SPODEvent struct {
	Type K8SPODEventType // add, delete, update
	Pod  *api.Pod
}

type K8SPODMonitor struct {
	ep      *K8SEndpoint
	ch      chan *K8SPODEvent
	monitor *cache.ListWatch
}

func (ep *K8SEndpoint) GetClient() *kubernetes.Clientset {
	if ep != nil {
		return ep.rpc
	}

	return nil
}

func NewK8SEndpoint(kubeconfig string) (*K8SEndpoint, error) {
	var config *kclient.Config
	var err error

	if kubeconfig == "" {
		log.Println("Using in cluster configuration")
		config, err = kclient.InClusterConfig()
	} else {
		log.Println("Using out of cluster configuration")
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
	}
	if err != nil {
		return nil, err
	}

	rpc, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	return &K8SEndpoint{
		config: config,
		rpc:    rpc,
	}, nil
}

func NewK8SPODMonitor(ep *K8SEndpoint, evChan chan *K8SPODEvent, ns, labelSelector, fieldSelector string) (*K8SPODMonitor, error) {
	if ep == nil {
		return nil, fmt.Errorf("no endpoint")
	}

	if ns == "" {
		ns = api.NamespaceAll
	}

	optionsModifier := func(options *metav1.ListOptions) {
		if labelSelector != "" {
			options.LabelSelector = labelSelector
		}

		if fieldSelector != "" {
			options.FieldSelector = fieldSelector
		}
	}

	monitor := cache.NewFilteredListWatchFromClient(
		ep.rpc.CoreV1().RESTClient(),
		"pods",          // resource
		ns,              // namespace
		optionsModifier, // granular filter criteria
	)

	return &K8SPODMonitor{
		ep:      ep,
		ch:      evChan,
		monitor: monitor,
	}, nil
}

func (m *K8SPODMonitor) Run(ctx context.Context) error {
	_, ctrlr := cache.NewInformer(m.monitor, &api.Pod{}, 0, cache.ResourceEventHandlerFuncs{
		UpdateFunc: func(obj interface{}, newo interface{}) {
			oldp := obj.(*api.Pod)
			newp := newo.(*api.Pod)

			//log.Printf("old: %v/%v, new: %v/%v\n", oldp.Name, oldp.Status.Phase, newp.Name, newp.Status.Phase)

			m.ch <- &K8SPODEvent{
				Type: PODEventTypeDel,
				Pod:  oldp,
			}

			// if the old status does not match the new status,
			// and the current phase is running, then let's
			// send the add event.
			if oldp.Status.Phase != newp.Status.Phase {
				if newp.Status.Phase == api.PodRunning {
					m.ch <- &K8SPODEvent{
						Type: PODEventTypeAdd,
						Pod:  newp,
					}
				}
			}

		},
		DeleteFunc: func(obj interface{}) {
			pod := obj.(*api.Pod)

			//log.Printf("delete (%s)\n", pod.Status.Phase)

			msg := &K8SPODEvent{
				Type: PODEventTypeDel,
				Pod:  pod,
			}

			m.ch <- msg
		},
		AddFunc: func(obj interface{}) {
			pod := obj.(*api.Pod)

			msg := &K8SPODEvent{
				Type: PODEventTypeAdd,
				Pod:  pod,
			}

			m.ch <- msg
		},
	})

	ctrlr.Run(ctx.Done())

	return nil
}
