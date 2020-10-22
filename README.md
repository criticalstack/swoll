[![Build Status](https://drone.cstack.co/api/badges/criticalstack/swoll/status.svg)](https://drone.cstack.co/criticalstack/swoll)

![logo](media/logo.png) 

# Introduction
----

Swoll is an API which can give an administrator a deeper understanding of
kernel-level operations happening on a system. It is built primarily for use
inside a Kubernetes cluster as it is able to map system-level activity back to
the container in which sourced the event. 

Using Linux eBPF alongside a custom filtering engine and an advanced decoding
engine, swoll is able to quickly inspect activity from one or more containers
without severely impacting performance.

The code in which runs in the kernel has a simple yet flexible filtering
mechanism which is used to remove noise and reduce overhead when tracing large
clusters.

Swoll also has the ability to collect very detailed statistical information
about a running cluster with little to no overhead. This data is exported from
each running instance in Prometheus format.

Since this project is primarily focused on analyzing Kubernetes clusters, most
of the tooling included within this project assumes it is being run inside said
cluster. Though it is fairly trivial to write tooling which bipasses kubernetes
alltogether, for example:

```go
// a very basic non-kube execve tracer.
package main
import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"github.com/criticalstack/swoll/pkg/event"
	"github.com/criticalstack/swoll/pkg/kernel"
	"github.com/criticalstack/swoll/pkg/kernel/filter"
)

func dumpEvent(raw []byte, _ uint64) error {
	msg := new(event.TraceEvent).Ingest(raw)
	fmt.Printf("[%s] %s err=%s\n", msg.Comm, msg.Argv.String(), msg.Error.ColorString())
	return nil
}

func main() {
	bpf, _ := ioutil.ReadFile("internal/bpf/probe.o")
	probe, _ := kernel.NewProbe(bytes.NewReader(bpf), nil)
	probe.InitProbe()

	filter, _ := filter.NewFilter(probe.Module())
	filter.AddSyscall("execve", 0)
	probe.Run(context.Background(), dumpEvent)
	select {}
}
```

Otherwise it is suggested to use the internal "hub" API when communicating with
Kubernetes as this makes life much easier. Here is a quick example that attempts
to find a local k8s deployment (using `cinder`) as a pivot-point:

```go
package main

import (
	"context"
	"fmt"
	"log"
	"os/exec"
	"strconv"
	"strings"

	"github.com/criticalstack/swoll/api/v1alpha1"
	"github.com/criticalstack/swoll/internal/pkg/hub"
	"github.com/criticalstack/swoll/pkg/event"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func findLocalPID() int {
	output, _ := exec.Command("docker", "inspect", "cinder", "--format", "{{.State.Pid}}").Output()
	p, _ := strconv.Atoi(strings.TrimSpace(string(output)))
	return p
}

func main() {
	swHub, err := hub.NewHub(&hub.Config{
		AltRoot:     fmt.Sprintf("/proc/%d/root", findLocalPID()),
		BPFObject:   "internal/bpf/probe.o",
		CRIEndpoint: "$root/run/containerd/containerd.sock",
		K8SEndpoint: "/home/lz/.kube/config"})
	if err != nil {
		log.Fatal(err)
	}

	spec := &v1alpha1.Trace{
		Spec: v1alpha1.TraceSpec{
			FieldSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{"status.phase": "Running"},
			},
			Syscalls: []string{"execve", "openat"},
		},
	}

	job := hub.NewJob(spec)

	go swHub.Run(context.TODO())
	go swHub.RunJob(job)

	swHub.AttachTrace(spec, func(s string, e *event.TraceEvent) {
		fmt.Printf("container=\"%s\", comm=\"%s\", err=%s :: %s\n", e.Container.FQDN(), e.Comm, e.Error.String(), e.Argv)
	})

	select {}
}
```

# Installation

See [BUILD INSTRUCTIONS](BUILDING.md)

# Usage

## swoll server 

The `swoll server` is to be run on all available kubernetes workers. It accepts
jobs on behalf of a client. It maintains all state and is able to route streams
of events to different clients based on specified criteria.

An example optimization would be something like the following:

`job-A` requests the syscalls `execve, openat` to be dumped for all containers
matching the label `app=nginx`.

`job-B` requests the single syscall `execve` to be dumped for containers
matching the label `type=production`. 

The label `app=nginx` matches against `container-A` and `container-B`, while the
label `type=production` matches `container-B` and `container-C`. 

When `job-A` is created, it creates the following filters:

```
add syscalls [execve, openat] to container(container-A) 
add syscalls [execve, openat] to container(container-B)
```

When `job-B` is created, the following filters are created:

```
add syscalls [execve] to container(container-C)
```

Note `job-B` did not create a filter for `execve` on `container-B`, as this rule
is already running. The server will internally make a copy of the stream for
`job-A:container-B:execve` into `job-B`. 

If `job-A` completes before `job-B`, the stream for `job-A:container-B:execve`
migrates over to `job-B` and does not remove the filter.


### Testing the Server Locally

Note: This assumes you have a kubernetes cluster running on your system. 

1. Find a PID which has the CRI socket, if Cinder is being used, the following command can be run:

   ```
   $ export PID=`ps auxwww | grep containerd.sock | grep runc | tail -n 1 | awk '{print $2}'`
   $ sudo ./bin/swoll server -k ~/.kube/config -A /proc/$PID/root -r '$root/run/containerd/containerd.sock' -b internal/bpf/probe.o 
   ```
   
2. Create a file containing the trace specification:

   ```
   cat << EOF >> traceSpec.json
   {
    "labelSelector": {
     "matchLabels": {
       "k8s-app": "cilium"
     }
    },
    "syscalls": [
       "getsockname",
       "socket",
       "accept4",
       "setsockopt",
       "getsockopt"
    ]
   }
   EOF
   ```

3. To run the job on the local server:

     ```
     ./bin/swoll client --endpoints 127.0.0.1:9095 create -f traceSpec.json  -n kube-system --oneshot
     ```


## swoll trace

The `trace` command allows a user to run ad-hoc traces on the commandline. Here
is some example usage:

```
$ sudo ./bin/swoll trace    \
    -k ~/.kube/config       \
    -b internal/bpf/probe.o \
    -f status.phase=Running \
    -s execve,openat        \
    -A /proc/1337/root      \
    -n swoll              \
    -r '$root/run/containerd/containerd.sock' \
    app=nginx-with-writer
```

Let's break this one down line by line.

`-k ~/.kube/config` : if you're running this command outside of the kubernetes
cluster, you must supply a valid configuration.

`-b internal/bpf/probe.o` : the path to the compiled eBPF object

`-f status.phase=Running` : use a kubernetes [field-selector](https://kubernetes.io/docs/concepts/overview/working-with-objects/field-selectors/) to narrow down containers to monitor. In this case, we only want to match on containers in the "Running" state. If you wanted to match a specific POD you could add `metadata.name=<POD_NAME>`.

`-s execve,openat` : Inform the application to monitor only the system calls `execve` and `openat`.

`-A /proc/1337/root` : The "Alernate root-directory". Using this, the tool will treat this value as the tools `/`. So if you use the keyword `$root/etc/passwd` in an argument, it is iterpreted as `/proc/1337/root/etc/passwd`. In this case, `/proc/1337/root` points to the root-filesystem of a process running inside my [cinder](https://github.com/criticalstack/crit) kubernetes cluster.  If that makes sense...

`-r '$root/run/containerd/containerd.sock'` : In order to resolve kernel events to the kubernetes container in which it was sourced, the tool needs to know where the hosts [CRI socket](https://kubernetes.io/blog/2016/12/container-runtime-interface-cri-in-kubernetes/). In this case, it is prefixed with `$root`, so it will take the `-A` (alt-root) option and prepend that to the lookup. In this case, the CRI socket can be found at `/proc/1337/root/run/containerd/containerd.sock`

`-n syswsall` : if this flag is supplied, you will only see traces on hosts in this kubernetes namespace. In this case `swoll` 

`app=nginx-with-writer` : only trace hosts/PODS that match this kubernetes [label selector](https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/)

### swoll client

The `client` command can be used to interact directly with a running probe.

## swoll controller (Kubernetes CRD controller)

The CRD controller for kubernetes allows an administrator to perform trace-jobs across the entire cluster using native kubernetes.

### Testing (assumes local cinder install)
1. make sure you have a probe running in your cluster: `kubectl apply -f internal/deploy/manifests`
2. make sure the CRD is installed, an easy way to do this is to type `make deploy`
3. start up a local controller (we don't deploy yet) `./bin/swoll controller -k ~/.kube/config`
    a. **Note**: by default, the image used for creating jobs is
    `cinderegg:5000/swoll:latest`, which is the default for cinder. You can
    change this by using `--image` or `-i` with whatever. 
4. start up a test pod which we will trace for `kubectl apply -n swoll -f https://gist.githubusercontent.com/NathanFrench/386cd8f0623ad227735f883909bc257c/raw/test.yaml` ([link](https:////gist.githubusercontent.com/NathanFrench/386cd8f0623ad227735f883909bc257c/raw/test.yaml)) 
5. tell kubernetes to run a trace on the test pod: `kubectl apply -n swoll -f https://gist.githubusercontent.com/NathanFrench/386cd8f0623ad227735f883909bc257c/raw/trace.yaml` ([link](https://gist.githubusercontent.com/NathanFrench/386cd8f0623ad227735f883909bc257c/raw/trace.yaml))
6. type `kubectl get traces -n swoll`

You should see something like the following:

```
$ kubectl get traces -n swoll
NAME            NAME            JOB                      SYSCALLS                                                      STATE
monitor-nginx   monitor-nginx   sw-monitor-nginx-xjcpm   [execve accept4 accept socket listen getsockopt setsockopt]   Complete
```

7. The job `sw-monitor-nginx-xjcpm` was created, so we can query its logs: `kubectl logs job/sw-monitor-nginx-xjcpm -n swoll -f`

You should see something like the following:

```
$ kubectl logs job/sw-monitor-nginx-xjcpm -n swoll -f
Endpoint 172.19.0.2:9095 created monitor-nginx
indexwriter.nginx-provider.swoll: [sh] sys_execve(filename=(const char *)/bin/date, argv[]=(char * const)   ) err=OK ses=1
indexwriter.nginx-provider.swoll: [sh] sys_execve(filename=(const char *)/bin/sleep, argv[]=(char * const)1  KUBERNETES_PORT=tcp://10.254.0.1:443 ) err=OK ses=1
```

### What happened?

You have a probe running and it listens for jobs, those jobs are created by the
controller. The controller gets a trace message from the api-server, starts up a
kubernetes job that connects to each probe and tells it to start tracing.

