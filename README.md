![Build Status](https://github.com/criticalstack/swoll/workflows/Lint%20and%20test%20Swoll/badge.svg)

<p align="center">
  <img src="media/swoll-banner.png">
</p>

# QUICK

Just wanna test things out? Here is an example command to run that doesn't require k8s.

```
docker run --rm -it --pid=host --privileged criticalstack/swoll:latest trace --no-containers -s execve,openat
```

# Introduction

Swoll is an **experimental** suite of applications and APIs for monitoring kernel-level activity on a live Kubernetes cluster, mostly written in the Golang programming language, strewn about with bits and bobs of C and Yaml. 

Using simple counters and a minimal state, Swoll can report on a wide bevy of information on system calls being made by or from a container running inside a Kubernetes cluster. Each metric for both timing and counting contains the following information:

* Syscall
  - Return Status
  - Classification
  - Group
* Kubernetes information
  - Namespace
  - Pod
  - Container

Aggregating data in this manner allows a user to monitor every call and its resulting return status for every container in every Kubernetes Pod. For example, one can query the total count of calls to the function `sys_openat` sourced from a specific container in the pod `coredns` in the namespace `kube-system` that resulted in a "No such file or directory" error.

Metrics are exposed via the URI `/metrics` in `Prometheus` format, along with detailed charting examples (powered by e-charts) at the URI `/metrics/charts`.

**Example charts output**
![Charts](media/charts-ss.png)
_The above Sankey diagram displays the distribution of system calls in an attractive™ manner._

**Prometheus query examples** 
```sh
$ promtool query instant https://prometheus.local '
  sort_desc(
   sum(
    swoll_node_metrics_syscall_count{
     namespace="kube-system"
    }) by (err))'

{err="ETIMEDOUT"}       => 745430
{err="EAGAIN"}          => 254506
{err="EINPROGRESS"}     => 2217
{err="EPERM"}           => 1779
{err="ENOENT"}          => 1288
{err="EPROTONOSUPPORT"} => 60
{err="EINTR"}           => 46
```
_Total count of syscalls grouped by the return-status originating from the Kubernetes namespace `kube-system`_

```sh
$ promtool query instant https://prometheus.local '
  sort_desc(
   sum(
    swoll_node_metrics_syscall_count{
     namespace="kube-system",
     syscall="sys_openat"
    }) by (namespace,pod))'

{namespace="kube-system", pod="kube-proxy-27xrc"}                 => 1260
{namespace="kube-system", pod="cilium-shskf"}                     => 670
{namespace="kube-system", pod="kube-apiserver-cinder"}            => 471
{namespace="kube-system", pod="coredns-7jhhg"}                    => 297
{namespace="kube-system", pod="kube-controller-manager-cinder"}   => 191
{namespace="kube-system", pod="cilium-operator-657978fb5b-cjx72"} => 78
```
_Count all calls to the function `sys_openat` grouped by Kubernetes Pod, and namespace_

```sh
$ promtool query instant https://prometheus.local '
  sort_desc(
   avg by (container, pod, namespace, syscall) (
    rate(
     swoll_node_metrics_syscall_count { err != "OK" }[5m]
     offset 5m
    )) /
   avg by (container, pod, namespace, syscall) (
    rate(
     swoll_node_metrics_syscall_count{ err != "OK" }[5m]
    )
   ))'
{container="operator", namespace="kube-system", pod="cilium-operator", syscall="sys_epoll_ctl"} => 2.0
{container="coredns",  namespace="kube-system", pod="coredns-7jhhg",   syscall="sys_futex"}     => 1.1
{container="operator", namespace="kube-system", pod="cilium-operator", syscall="sys_read"}      => 1.0
{container="agent",    namespace="kube-system", pod="cilium-shskf",    syscall="sys_futex"}     => 1.0
```
_Query the relative change in the rate of calls that incurred an error compared to the previous 5 minutes grouped by container, Pod, namespace, and syscall_ 

---

While metrics by themselves are great and all, `swoll` also provides a
Kubernetes-native interface for creating, collecting, and presenting detailed
real-time logs of system activity. 

Take the following Trace configuration as an example:

```yaml
apiVersion: tools.swoll.criticalstack.com/v1alpha1
kind: Trace
metadata:
  name: trace-nginx-hosts
  namespace: swoll
spec:
  syscalls:
    - connect
    - accept4
    - bind
    - listen
    - execve
    - openat
  labelSelector:
      matchLabels:
          app: "nginx"
  fieldSelector:
      matchLabels:
          status.phase: "Running"
```

When applied, `swoll` will start tracing the system-calls `connect`, `accept4`, `bind`, `listen`, `execve`, and `openat` for any containers that match the pod-label `app=nginx`, and the field-label `status.phase=Running` (match only running containers). 

Once started, the raw JSON events are retrieved via `kubectl logs`:

```sh
$ kubectl logs -l sw-job=trace-nginx-hosts -n swoll | head -n 1 | jq .
```

```json
{
  "payload": {
    "syscall": {
      "nr": 257,
      "name": "sys_openat",
      "class": "FileSystem",
      "group": "Files"
    },
    "pid": 3797092,
    "tid": 3797092,
    "uid": 0,
    "gid": 0,
    "comm": "sh",
    "session": 1,
    "container": {
      "id": "13765a70dfbb1b35ebff60c04ddfebf9177715bcf79e67279d4e8128799501bf",
      "pod": "nginx-provider",
      "name": "indexwriter",
      "image": "sha256:1510e850178318cd2b654439b56266e7b6cbff36f95f343f662c708cd51d0610",
      "namespace": "swoll",
      "labels": {
        "io.kubernetes.container.name": "indexwriter",
        "io.kubernetes.pod.name": "nginx-provider",
        "io.kubernetes.pod.namespace": "swoll",
        "io.kubernetes.pod.uid": "4c16fc49-2c47-427d-b5d6-a222e65b76c9"
      },
      "pid": 408510,
      "pid-namespace": 4026535150
    },
    "error": "OK",
    "return": 3,
    "pid_ns": 4026535150,
    "uts_ns": 4026535144,
    "mount_ns": 4026535149,
    "start": 529490506498247,
    "finish": 529490506535997,
    "args": {
      "dir_fd": -100,
      "pathname": "/html/index․html",
      "flags": [
        "O_CREAT",
        "O_APPEND",
        "O_WRONLY"
      ]
    }
  }
}
```

![Running a Trace](media/running-a-trace.gif)
_A sweet gif showing a trace running... So 2020_


---

## Using the API to trace.

### Local, without Kubernetes resolution

In this example, we display how to utilize the `swoll` Golang API to initiate a local trace of the `execve` call without Kubernetes locally.

```go
package main

import (
    "bytes"
    "context"
    "fmt"
    "io/ioutil"

    "github.com/criticalstack/swoll/pkg/event"
    "github.com/criticalstack/swoll/pkg/event/call"
    "github.com/criticalstack/swoll/pkg/event/reader"
    "github.com/criticalstack/swoll/pkg/kernel"
    "github.com/criticalstack/swoll/pkg/kernel/filter"
)

func main() {
    // read local bpf object
    bpf, _ := ioutil.ReadFile("internal/bpf/probe.o")
    // create a probe object
    probe, _ := kernel.NewProbe(bytes.NewReader(bpf), nil)

    // initialize the underlying bpf tables
    probe.InitProbe()

    // create a new kernel-filter bound to the current bpf probe
    filt, _ := filter.NewFilter(probe.Module())
    // inform the probe we are interested in all execve
    filt.AddSyscall("execve", -1)

    // create an event reader for the probe
    reader := reader.NewEventReader(probe)
    // run the probe
    go reader.Run(context.Background())

    // where to store decoded events
    decoded := new(event.TraceEvent)

    for {
        // read a single message from the event queue from the kernel
        msg := <-reader.Read()
        // convert the raw data from the kernel into a proper TraceEvent object
        decoded.Ingest(msg)

        // fetch the arguments associated with the call
        args := decoded.Argv.Arguments()

        fmt.Printf("comm:%-15s pid:%-8d %s(%s)\n", decoded.Comm, decoded.Pid, decoded.Syscall, args)
    }
}
```

### Local, With Kubernetes

The easiest way to trace Kubernetes is to utilize the `Topology` API, which consists of an `Observer` and a `Hub`. A `Hub` is an abstraction around kernel filtering based on events sourced from the `Observer`. In this case, we will utilize a Kubernetes `Observer` which emits container-ready events for any POD events.

```go
package main

import (
    "context"
    "fmt"
    "io/ioutil"
    "os"
    "path/filepath"

    "github.com/criticalstack/swoll/api/v1alpha1"
    "github.com/criticalstack/swoll/internal/pkg/hub"
    "github.com/criticalstack/swoll/pkg/event"
    "github.com/criticalstack/swoll/pkg/event/call"
    "github.com/criticalstack/swoll/pkg/topology"
)

func main() {
    // read local bpf object
    bpf, _ := ioutil.ReadFile("internal/bpf/probe.o")
    kConfig := os.Getenv("HOME") + "/.kube/config"
    rootDir := "/proc/3796667/root"
    criSock := "/run/containerd/containerd.sock"

    // create a kubernetes observer
    kTopo, _ := topology.NewKubernetes(
        topology.WithKubernetesCRI(filepath.Join(rootDir, criSock)),
        topology.WithKubernetesConfig(kConfig),
        topology.WithKubernetesProcRoot(rootDir))

    // initialize an event hub and bind it to the kubernetes observer
    kHub, _ := hub.NewHub(&hub.Config{
        AltRoot:     rootDir,
        BPFObject:   bpf,
        CRIEndpoint: filepath.Join(rootDir, criSock),
        K8SEndpoint: kConfig}, kTopo)

    // run the event hub
    go kHub.Run(context.Background())

    // create a trace specification to monitor execve on all pods
    trace := &v1alpha1.Trace{
        Spec: v1alpha1.TraceSpec{
            Syscalls: []string{"execve"},
        },
        Status: v1alpha1.TraceStatus{
            JobID: "trace-nginx",
        },
    }

    // run the trace specification on the hub
    go kHub.RunTrace(trace)

    // attach to the running trace and print out stuff
    kHub.AttachTrace(trace, func(id string, ev *event.TraceEvent) {
        args := ev.Argv.Arguments()

        fmt.Printf("container=%s pod=%s namespace=%s comm:%-15s pid:%-8d %s(%s)\n",
            ev.Container.Name, ev.Container.Pod, ev.Container.Namespace,
            ev.Comm, ev.Pid, ev.Syscall, args)
    })

    select {}

}
```

This is pretty much the same as running:

```sh
swoll trace \
    --kubeconfig ~/.kube/config                                  \
    --altroot  /proc/3796667/root                                \
    --cri      /proc/3796667/root/run/containerd/containerd.sock \
    --syscalls execve
```


### Remote using the Client API

```go
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/criticalstack/swoll/api/v1alpha1"
	"github.com/criticalstack/swoll/pkg/client"
)

func main() {
	// create the trace specification
	spec := &v1alpha1.TraceSpec{
		Syscalls: []string{"execve"},
	}

	// connect to a probe running on 172.19.0.3:9095 with SSL disabled
	ep := client.NewEndpoint("172.19.0.3", 9095, false)
	ctx, cancel := context.WithCancel(context.Background())
	// channel where events are written to
	outch := make(chan *client.StreamMessage)
	// signal channel
	sigch := make(chan os.Signal, 1)
	signal.Notify(sigch, os.Interrupt, syscall.SIGTERM)

	// create a trace with the name of "trace-stuff" inside the namespace
	// "kube-system"
	tr, err := ep.CreateTrace(ctx, "trace-stuff", "kube-system", spec)
	if err != nil {
		log.Fatal(err)
	}

	var wg sync.WaitGroup

	go func() {
		wg.Add(1)
        // Blocking reader 
		ep.ReadTraceJob(ctx, tr.Status.JobID, outch)
        // If ReadTraceJob returns, let's just delete this current job from the
        // server
		ep.DeleteTraceJob(ctx, tr.Status.JobID)
		wg.Done()
	}()

Loop:
	for {
		select {
		case ev := <-outch:
			fmt.Println(ev)
		case <-sigch:
			break Loop
		}
	}

    // notify ReadTraceJob to halt.
    cancel()
    // wait for the job to be deleted
	wg.Wait()
}
```

## swoll-trace

```
./bin/swoll trace -h
Kubernetes-Aware strace(1)

Usage:
  swoll trace [flags]

Flags:
  -f, --field-selector string   field selector
  -h, --help                    help for trace
  -n, --namespace string        namespace to read from
      --no-containers           disable container/k8s processing
  -o, --output string           output format (default "cli")
  -s, --syscalls strings        comma-separated list of syscalls to trace

Global Flags:
  -A, --altroot string          alternate root CWD
  -b, --bpf string              alternative external bpf object
  -r, --cri string              path to the local CRI unix socket
  -k, --kubeconfig string       path to the local k8s config instance (defaults to incluster config)
      --no-detect-offsets       Do not automatically determine task_struct member offsets (uses default offsets)
      --nsproxy-offset string   Offset (in hex) of task_struct->nsproxy
      --pidns-offset string     Offset (in hex) of pid_namespace->ns
  -V, --version                 show version information
```

To run a simple trace on a system without Kubernetes resolution:

```
sudo ./bin/swoll trace --no-containers -s execve
[sudo] password for lz:
2020/11/15 13:45:08 trace.go:76: Checking install...
2020/11/15 13:45:08 selftest.go:114: checking capabilities
2020/11/15 13:45:08 selftest.go:119: checking for proper mounts
2020/11/15 13:45:08 selftest.go:134: checking kernel-config (if available)
2020/11/15 13:45:09 offsetter.go:234: warning: couldn't find address for sym utcns_get
2020/11/15 13:45:10 offsetter.go:250: info: likelyOffset addr=0xae0, count=7
2020/11/15 13:45:10 offsetter.go:222: info: pidns->ns_common likelyOffset addr=0xb8, count=5
2020/11/15 13:45:10 offsetter.go:312: Setting task_struct->nsproxy offset to: ae0
2020/11/15 13:45:10 offsetter.go:331: Setting pid_namespace->ns offset to: b8
[        dockerd/475417  ] (OK) execve((const char *)filename=/usr/sbin/runc, (char * const)argv[]=--version   )
[        dockerd/475424  ] (OK) execve((const char *)filename=/usr/bin/docker-init, (char * const)argv[]=--version   )
[        dockerd/475425  ] (OK) execve((const char *)filename=/usr/sbin/runc, (char * const)argv[]=--version   )
[        dockerd/475432  ] (OK) execve((const char *)filename=/usr/bin/docker-init, (char * const)argv[]=--version   )
[        dockerd/475433  ] (OK) execve((const char *)filename=/usr/sbin/runc, (char * const)argv[]=--version   )
[        dockerd/475440  ] (OK) execve((const char *)filename=/usr/bin/docker-init, (char * const)argv[]=--version   )
[        dockerd/475441  ] (OK) execve((const char *)filename=/usr/sbin/runc, (char * const)argv[]=--version   )
[        dockerd/475448  ] (OK) execve((const char *)filename=/usr/bin/docker-init, (char * const)argv[]=--version   )
```

If you have the `swoll-server` running, you can run traces from there like so:

```
$ kubectl exec -it swoll-server-POD -- swoll trace --cri /run/containerd/containerd.sock --syscalls openat,execve

kube-apiserver.kube-apiserver-cinder.kube-system: [kube-apiserver] (OK) openat((int)dirfd=AT_FDCWD, (const char *)pathname=/etc/kubernetes/pki/ca.crt, (int)flags=O_CLOEXEC)
kube-apiserver.kube-apiserver-cinder.kube-system: [kube-apiserver] (OK) openat((int)dirfd=AT_FDCWD, (const char *)pathname=/etc/kubernetes/pki/apiserver.crt, (int)flags=O_CLOEXEC)
kube-apiserver.kube-apiserver-cinder.kube-system: [kube-apiserver] (OK) openat((int)dirfd=AT_FDCWD, (const char *)pathname=/etc/kubernetes/pki/front-proxy-ca.crt, (int)flags=O_CLOEXEC)
kube-apiserver.kube-apiserver-cinder.kube-system: [kube-apiserver] (OK) openat((int)dirfd=AT_FDCWD, (const char *)pathname=/etc/kubernetes/pki/apiserver.key, (int)flags=O_CLOEXEC)
kube-apiserver.kube-apiserver-cinder.kube-system: [kube-apiserver] (OK) openat((int)dirfd=AT_FDCWD, (const char *)pathname=/etc/kubernetes/pki/ca.crt, (int)flags=O_CLOEXEC)
kube-apiserver.kube-apiserver-cinder.kube-system: [kube-apiserver] (OK) openat((int)dirfd=AT_FDCWD, (const char *)pathname=/etc/kubernetes/pki/front-proxy-ca.crt, (int)flags=O_CLOEXEC)
local-path-provisioner.local-path-storage-74cd8967f5-f7p5b.local-path-storage: [local-path-prov] (OK) openat((int)dirfd=AT_FDCWD, (const char *)pathname=/var/run/secrets/kubernetes.io/serviceaccount/token, (int)flags=O_CLOEXEC)

```

## swoll-server

The server acts as a buffer between the kernel and userland. It controls the
filtering rules to a single BPF object, and multiplexes out streams of data to
clients.

Take the following TraceJob definition:

```yaml
apiVersion: tools.swoll.criticalstack.com/v1alpha1
kind: Trace
metadata:
  name: monitor-nginx
spec:
  syscalls:
    - execve
    - openat
  labelSelector:
      matchLabels:
          app: "nginx"
  fieldSelector:
      matchLabels:
          status.phase: "Running"
```

When the server receives this request, it will start to monitor for any PODs
with the labels "app=nginx", and the phase of "Running". For every container in
a matched POD, the server will:

1. Look up the PID-namespace of the container
2. Insert two filters into the running BPF: `filter <pid-namespace>:execve` and
   `filter <pid-namespace>:openat`.
3. Output matched events to a job-queue in raw JSON format.

The server is intelligent enough not to duplicate rules, or accidentally delete
filters from another running job.

Once a server is running in a k8s cluster, utilize the `swoll client` command to
interact directly with the server.

## swoll-client

The client command is used to directly interact with one or more
`swoll-server`'s. 

```
./bin/swoll client create \
  --endpoints 172.19.0.3:9095,172.19.2.3:9095 \
  --syscalls execve,openat \
  --field-selector status.phase=Running \
  -n kube-system \
  --oneshot -o cli
  cilium-agent.cilium-cjdfv.kube-system: [cilium-agent] (OK) openat((int)dirfd=AT_FDCWD, (const char *)pathname=/proc/loadavg, (int)flags=O_CLOEXEC)
cilium-agent.cilium-cjdfv.kube-system: [cilium-agent] (OK) openat((int)dirfd=AT_FDCWD, (const char *)pathname=/proc/loadavg, (int)flags=O_CLOEXEC)
cilium-operator.cilium-operator-657978fb5b-2ntrt.kube-system: [cilium-operator] (OK) openat((int)dirfd=AT_FDCWD, (const char *)pathname=/var/run/secrets/kubernetes.io/serviceaccount/token, (int)flags=O_CLOEXEC)
manager.swoll-controller-swoll-d944d75f-ktdn6.kube-system: [      swoll] (OK) openat((int)dirfd=AT_FDCWD, (const char *)pathname=/var/run/secrets/kubernetes.io/serviceaccount/token, (int)flags=O_CLOEXEC)
cilium-agent.cilium-cjdfv.kube-system: [cilium-agent] (OK) openat((int)dirfd=AT_FDCWD, (const char *)pathname=/proc/loadavg, (int)flags=O_CLOEXEC)
```


## swoll-controller

*Monitor. Consume. React.*

* Kernel
  - filtering
  - collection
  - distribution
  - metrics
* Userland
  - collection
  - translation
  - presentation


# Building

See [BUILD INSTRUCTIONS](BUILDING.md)


## Contributing
Any contributors must accept and [sign the CLA](https://cla-assistant.io/criticalstack/swoll).
This project has adopted the [Capital One Open Source Code of conduct](https://developer.capitalone.com/resources/code-of-conduct).
