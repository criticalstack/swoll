package podmon

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"

	"github.com/criticalstack/swoll/pkg/types"
	"github.com/gobwas/glob"

	api "k8s.io/api/core/v1"
)

const (
	UpdateAdd = iota + 1
	UpdateDel
	POD_LABEL_ENABLE_DEFAULT = "syswall!=false"
)

var (
	ErrNoCRIForNamespace     = errors.New("no cri for namespace")
	ErrNoPodDataForNamespace = errors.New("no pod data for namespace")
	ErrPodmonNotInitialized  = errors.New("podmon not initialized")
	ErrNoMatchingContainer   = errors.New("no matching container")
)

type (
	Config struct {
		// The container runtime socket
		CRIEndpoint string
		// The k8s configuration file.
		K8SEndpoint string
		// The default kubernetes namespace
		K8SNamespace string
		// A label-match to use for pod-selection
		PodLabelEnable string
		// A field-match to use for pod-selection
		FieldSelector string
		// Alternate / directory to gather fs data from (e.g., /proc/<pid>/root...)
		// This is used as the basedir for where ProcFS entries are listed. If your
		// procfs lives outside of the standard /, then set this in order to not get
		// invalid messages.
		AltRoot string
	}

	PodData struct {
		pod        *api.Pod
		containers []*CRIContainer
	}

	pidNamespace int
	mntNamespace int

	containerKey struct {
		p, m int
	}

	UpdateType     int
	UpdateCallback func(t UpdateType, c *CRIContainer)

	PodMon struct {
		config    *Config
		k8smon    *K8SPODMonitor
		criep     *CRIEndpoint
		podCache  map[pidNamespace]*PodData
		criCache  map[mntNamespace]*CRIContainer
		contCache map[containerKey]*types.Container
		k8sch     chan *K8SPODEvent
		mu        sync.RWMutex
	}
)

// NewPodMon creates all the underlying methods to correlate pods events to
// their underlying containers.
//
// Listen for POD add/remove/update events from kubernetes, and when an
// event fires, query the local CRI to determine if the local kubelet owns
// it. And if it does, update a cache where the key is the pid namespace of
// the container, and the value being the POD information.
func NewPodMon(config *Config) (*PodMon, error) {
	if config == nil {
		return nil, fmt.Errorf("no config")
	}

	if config.AltRoot != "" {
		// if we have an alternate root setting, and the endpoints start with
		// "$root", use the AltRoot as the CWD for any further lookups, whether
		// that be for /proc, or for configurations.
		//
		// mainly here for development reasons, if you're able to see your k8s
		// node via /proc/<pid>/root, you can set the AltRoot to this, and
		// namespace lookups will look at /proc/<pid>/root/proc/...
		// cri socket will look at /proc/<pid>/root/path/to/cri.sock
		// etc...
		if strings.HasPrefix(config.CRIEndpoint, "$root") {
			config.CRIEndpoint = config.AltRoot + config.CRIEndpoint[5:]
		}

		if strings.HasPrefix(config.K8SEndpoint, "$root") {
			config.K8SEndpoint = config.AltRoot + config.K8SEndpoint[5:]
		}
	}

	criep, err := NewCRIEndpoint(config.CRIEndpoint)
	if err != nil {
		return nil, err
	}

	k8sep, err := NewK8SEndpoint(config.K8SEndpoint)
	if err != nil {
		return nil, err
	}

	if config.K8SNamespace == "" {
		config.K8SNamespace = api.NamespaceAll
	}

	ch := make(chan *K8SPODEvent)
	k8smon, err := NewK8SPODMonitor(k8sep, ch, config.K8SNamespace, config.PodLabelEnable, config.FieldSelector)
	if err != nil {
		return nil, err
	}

	return &PodMon{
		config:    config,
		k8smon:    k8smon,
		criep:     criep,
		podCache:  make(map[pidNamespace]*PodData),
		criCache:  make(map[mntNamespace]*CRIContainer),
		contCache: make(map[containerKey]*types.Container),
		k8sch:     ch,
	}, nil
}

// findContainers searches through local running containers via CRI using
// the pre-generated pod.name label and namespace set on the container.
func (p *PodMon) findContainers(podName string, nsName string, doGlob bool) ([]*CRIContainer, error) {
	containers, err := p.criep.GetContainers(context.TODO(), p.config.AltRoot)
	if err != nil {
		return nil, err
	}

	ret := make([]*CRIContainer, 0)

	for _, container := range containers {
		labels := container.Labels()

		// if the value of this label matches the name of the pod
		// we are looking for, then it's a match.
		if criPod, ok := labels["io.kubernetes.pod.name"]; ok {
			if criNs, ok := labels["io.kubernetes.pod.namespace"]; ok {
				if doGlob {
					if glob.MustCompile(nsName).Match(criNs) && glob.MustCompile(podName).Match(criPod) {
						ret = append(ret, container)
					}
				} else {
					if criPod == podName && criNs == nsName {
						ret = append(ret, container)
					}
				}
			}
		}
	}

	if len(ret) == 0 {
		return nil, ErrNoMatchingContainer
	}

	return ret, nil
}

// updateCache will, depending on the event type, update (add,remove)
// the pod cache (key of pid namespace)
func (p *PodMon) updateCache(pod *api.Pod, t K8SPODEventType, cb UpdateCallback) error {
	if containers, err := p.findContainers(pod.Name, pod.Namespace, false); err == nil {
		for _, container := range containers {
			ns := container.PIDNamespace()
			mnt := container.MNTNamespace()

			if ns == -1 || mnt == -1 {
				continue
			}

			switch t {
			case PODEventTypeUpd:
				// update pod information: we must determine if this the POD
				// is already cached, and if so, we must cycle through every
				// container within the pod, and if this one is not found,
				// append it.
				if data, ok := p.podCache[pidNamespace(ns)]; ok {
					found := false

					// iterate over each container that is already in the list
					// of containers, and if it's found, we don't add it, otherwise
					// we append to the list.
					for _, c := range data.containers {
						if c == nil {
							continue
						}

						if container.id == c.id {
							found = true
							break
						}
					}

					if !found {
						data.containers = append(data.containers, container)
					}
				} else {
					// nothing found for this specific pod, this is an update
					// message, so maybe the pod is currently being processed.
					// insert it here.
					data := &PodData{
						pod:        pod,
						containers: make([]*CRIContainer, 1),
					}

					data.containers = append(data.containers, container)
					p.podCache[pidNamespace(ns)] = data
				}

				p.criCache[mntNamespace(mnt)] = container

				if cb != nil {
					// if a record has been updated, we are just going to be
					// lazy, and emit a delete and add event. Same outcome.
					log.Printf("[update] Sending Delete msg for %v (%v/%v)\n",
						container.name, container.pidNamespace, container.mntNamespace)

					p.mu.Unlock()
					cb(UpdateDel, container)
					p.mu.Lock()

					log.Printf("[update] Sending Add msg for %v (%v/%v)\n",
						container.name, container.pidNamespace, container.mntNamespace)

					p.mu.Unlock()
					cb(UpdateAdd, container)
					p.mu.Lock()
				}

			case PODEventTypeAdd:
				// new POD, create the data and append the current container.
				log.Printf("Sending ADD msg for %v (%v/%v)\n",
					container.name, container.pidNamespace, container.mntNamespace)

				data := &PodData{
					pod:        pod,
					containers: make([]*CRIContainer, 1),
				}

				data.containers = append(data.containers, container)

				p.podCache[pidNamespace(ns)] = data
				p.criCache[mntNamespace(mnt)] = container

				if cb != nil {
					// emit an Add event
					p.mu.Unlock()
					cb(UpdateAdd, container)
					p.mu.Lock()
				}

			case PODEventTypeDel:
				log.Printf("Sending DEL msg for %v (%v/%v)\n",
					container.name, container.pidNamespace, container.mntNamespace)

				// we can just remove the data from the cache.
				delete(p.podCache, pidNamespace(ns))
				delete(p.criCache, mntNamespace(mnt))
				delete(p.contCache, containerKey{ns, mnt})

				if cb != nil {
					// emit a Deletion event
					p.mu.Unlock()
					cb(UpdateDel, container)
					p.mu.Lock()
				}
			}
		}
	}

	return nil
}

func (p *PodMon) LookupPodDatabyNS(ns int) (*PodData, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	ret, err := p.LookupPodDatabyNSnoLock(ns)
	return ret, err
}

// LookupPodDatabyNS returns the cached PodData context for a given
// kernel pid-namespace.
func (p *PodMon) LookupPodDatabyNSnoLock(ns int) (*PodData, error) {
	if poddata, ok := p.podCache[pidNamespace(ns)]; ok {
		return poddata, nil
	}

	return nil, ErrNoPodDataForNamespace
}

// LookupCRIbyNS returns the cached CRI container context for a given
// kernel mnt-namespace.
func (p *PodMon) LookupCRIbyNS(ns int) (*CRIContainer, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	ret, err := p.LookupCRIbyNSnoLock(ns)
	return ret, err
}

func (p *PodMon) LookupCRIbyNSnoLock(ns int) (*CRIContainer, error) {
	if c, ok := p.criCache[mntNamespace(ns)]; ok {
		return c, nil
	}

	return nil, ErrNoCRIForNamespace
}

// Run will process k8s messages and correlate them with CRI queries.
func (p *PodMon) Run(ctx context.Context, cb UpdateCallback) error {
	//nolint:errcheck
	go p.k8smon.Run(ctx)

	for {
		select {
		case event := <-p.k8sch:
			p.mu.Lock()
			//nolint:errcheck
			p.updateCache(event.Pod, event.Type, cb)
			p.mu.Unlock()
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (p *PodMon) lookupContainer(pidns, mntns int) *types.Container {
	if c, ok := p.contCache[containerKey{pidns, mntns}]; ok {
		return c
	}

	return nil
}

// LookupContainer fetches the types.Container information via a
// kernel-namespace (PID and MNT).
func (p *PodMon) LookupContainer(pidns int, mntns int) (*types.Container, error) {
	if p == nil {
		return nil, ErrPodmonNotInitialized
	}

	p.mu.RLock()
	if container := p.lookupContainer(pidns, mntns); container != nil {
		p.mu.RUnlock()
		return container, nil
	}

	poddata, err := p.LookupPodDatabyNSnoLock(pidns)
	if err != nil {
		p.mu.RUnlock()
		return nil, err
	}

	cri, err := p.LookupCRIbyNSnoLock(mntns)
	if err != nil {
		p.mu.RUnlock()
		return nil, err
	}
	p.mu.RUnlock()
	p.mu.Lock()

	container := &types.Container{
		ID:           cri.ID(),
		Name:         cri.Name(),
		Pod:          poddata.PodName(),
		Namespace:    poddata.PodNamespace(),
		PodSandboxID: cri.PodSandboxID(),
		Image:        cri.Image(),
		Labels:       cri.GetLabels(),
	}

	p.contCache[containerKey{pidns, mntns}] = container
	p.mu.Unlock()
	return container, nil
}

func (p *PodMon) LookupContainerNoLock(pidns int, mntns int) (*types.Container, error) {
	if p == nil {
		return nil, ErrPodmonNotInitialized
	}

	if container := p.lookupContainer(pidns, mntns); container != nil {
		return container, nil
	}

	poddata, err := p.LookupPodDatabyNSnoLock(pidns)
	if err != nil {
		return nil, err
	}

	cri, err := p.LookupCRIbyNSnoLock(mntns)
	if err != nil {
		return nil, err
	}

	container := &types.Container{
		ID:           cri.ID(),
		Name:         cri.Name(),
		Pod:          poddata.PodName(),
		Namespace:    poddata.PodNamespace(),
		PodSandboxID: cri.PodSandboxID(),
		Image:        cri.Image(),
		Labels:       cri.GetLabels(),
	}

	p.contCache[containerKey{pidns, mntns}] = container
	return container, nil
}

func (p *PodMon) matchContainers(name, pod, ns string) []*types.Container {
	ret := make([]*types.Container, 0)

	for _, v := range p.contCache {
		if ns != "" && !glob.MustCompile(ns).Match(v.Namespace) {
			continue
		}

		if pod != "" && !glob.MustCompile(pod).Match(v.Pod) {
			continue
		}

		if name != "" && !glob.MustCompile(pod).Match(v.Name) {
			continue
		}

		ret = append(ret, v)
	}

	return ret
}

// MatchContainer will iterate over every entry in the container cache and
// return the Container in which has all three matching pod/name/namespace
// any variable in which is empty, will not be used for evaluation.
func (p *PodMon) MatchContainers(name, pod, ns string) ([]*types.Container, error) {
	if p == nil {
		return nil, ErrPodmonNotInitialized
	}

	p.mu.RLock()
	defer p.mu.RUnlock()

	ret := p.matchContainers(name, pod, ns)
	return ret, nil
}

func (p *PodData) PodName() (name string) {
	if p != nil {
		name = p.pod.Name
	}
	return
}

func (p *PodData) PodNamespace() (ns string) {
	if p != nil {
		ns = p.pod.Namespace
	}

	return
}

// ContainerCache returns the cached containers current known.
func (p *PodMon) ContainerCache() map[containerKey]*types.Container {
	if p != nil {
		return p.contCache
	}

	return nil
}

func (c containerKey) String() string { return fmt.Sprintf("%d/%d", c.p, c.m) }
