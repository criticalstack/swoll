While there are several ways to utilize the Swoll API to create and manage traces, the Topology method is preferred, especially on container orchestration systems such as Kubernetes.

To adequately understand what this package does, it is best to start with a little primer on how Swoll interacts with the running BPF to create, filter, and emit events from the kernel back to userland.

The Swoll BPF has a simple userspace-configurable filtering mechanism that allows us to permit or deny a syscall from being monitored. Optionally, each call we monitor can be associated with a kernel namespace. For example, a user can request to see only the syscall "open" in the Linux PID Namespace `31337`. The kernel will silently drop any events that do not match this particular rule.

```go
package main

import (
    "github.com/criticalstack/swoll/pkg/kernel"
    "github.com/criticalstack/swoll/pkg/kernel/assets"
    "github.com/criticalstack/swoll/pkg/kernel/filter"
)

func main() {
    probe, _ := kernel.NewProbe(assets.LoadBPFReader(), nil)
    filter, _ := filter.NewFilter(probe.Module())

    filter.AddSyscall("open", 31337)
}
````

Manually maintaining this filter can become tedious when we start speaking of traces in non-specifics and abstracts. For example, this TraceSpec YAML configuration does not indicate **what** hosts it will monitor, just that it will begin watching any host that matches these meta-attributes.

```yaml
# Monitor the calls "openat", and "execve" from any host in
# the namespace "default" with the label 
# app.kubernetes.io/name set to the value "nginx"
apiVersion: tools.swoll.criticalstack.com/v1alpha1
kind: Trace
metadata:
  name: monitor-nginx
  namespace: default
spec:
  syscalls:
    - openat
    - execve
  labelSelector:
      matchLabels:
          app.kubernetes.io/name: "nginx"
```

And it is with this concept of being abstract where the Topology package starts to shine; it is the glue that binds the symbolic to the real and the logic that governs the flow of information through the system.

Two primary components make up a Topology: an `Observer` and a `Hub`; the Observer has the simple task of monitoring container states and reporting any changes to the Hub. The Hub then uses these update notifications to make changes to the kernel filtering in real-time.

The Hub also acts as a runtime optimizer, de-duplicating rules, pruning state, maintaining metrics, and routing events to the proper endpoints with a straightforward goal: "One BPF To Mon Them All" without sacrificing performance for flexibility or vice-versa.

In the following example, we will define and run two "trace-jobs" using the Topology package, resulting in some events matching both outputs for the express purpose of explaining the BPF rule optimizer.

-----

### Load our BPF

```go
func main() {
    ctx := context.Background()
    bpf := assets.LoadBPFReader()
```

*And with `main`, we do begin...*

The Swoll API ships with a pre-compiled BPF object for `x86_64` which should work on any Linux kernel greater than v4.1. To use this, we load the code from the assets package. The return of `LoadBPFReader()` is a `bytes.Reader` object.

### Create our Observer

```go
    observer, err := topology.NewKubernetes(
        topology.WithKubernetesConfig(""),
        topology.WithKubernetesCRI("/run/containerd/containerd.sock"),
        topology.WithKubernetesNamespace(""),
        topology.WithKubernetesProcRoot("/"),
        topology.WithKubernetesLabelSelector("noSwoll!=true"),
        topology.WithKubernetesFieldSelector("status.phase=Running"),
    )
    if err != nil {
        log.Fatalf("Could not create the kubernetes observer: %v", err)
    }
```

Here we have created the first part of a `Topology`, the `Observer`. In thise case, the `Observer` will interact with Kubernetes and the CRI (Container Runtime Interface) to map numerical kernel-namespaces to a specific (k8s)Namespace/POD/container. There are a few `With` configuration directives set here, so let's go over each one individually:

```go
topology.WithKubernetesConfig("")
```

If this code was being run outside of the cluster (e.g., not an `in-cluster` deployment), the value of this option would be the fully-qualified path to your current kubernetes configuration file.

```go
topology.WithKubernetesCRI("/run/containerd/containerd.sock")
```

This is the path to the CRI socket file as seen by the host running this code. This socket must be readable via a shared mount.

```go
topology.WithKubernetesNamespace("")
```

You can tell our observer to limit the container search to a single kubernetes namespace. For the sake of brevity, we leave this empty. The result of which is monitoring container states in *all* namespaces.

```go
topology.WithKubernetesProcRoot("/")
```

The Observer uses ProcFS to derive what numerical kernel-namespaces a process belongs to. If that is mounted in a different directory outside of `/`, you would set it here.

```go
topology.WithKubernetesLabelSelector("noSwoll!=true")
```

This acts like a pre-filter for container events, essentially stating that any Pod/Container that has the label `noSwoll=true` should never be seen.

```go
topology.WithKubernetesFieldSelector("status.phase=Running")
```

Inform the Observer that we are only interested in containers that Kube has deemed as "running".

### Prime & Pump the Hub

```go
    hub, err := topology.NewHub(bpf, observer)
    if err != nil {
        log.Fatalf("Could not create the hub: %v", err)
    }
```

Creates a brand new Hub context, using the Kubernetes Observer object we just created.

```go    
    if err := hub.Probe().DetectAndSetOffsets(); err != nil {
        log.Fatalf("Could not detect offsets for running kernel: %v", err)
    }
```

This part is pretty important. The BPF needs to access various members of the
kernel's `struct task_struct` structure which can differ on every system. This
helper function `DetectAndSetOffsets` will poke at the memory of the running
kernel in order to determine and set these offsets.

### Run the Hub

```go
    go hub.MustRun(ctx)
```

This runs the Hub's event loop as a background task, silently maintaining the filters running general book-keeping operations.

### Define the Traces

```go
    trace1 := &v1alpha1.Trace{
        ObjectMeta: metav1.ObjectMeta{
            Namespace: "swoll-hub-test",
        },
        Spec: v1alpha1.TraceSpec{
            LabelSelector: metav1.LabelSelector{
                MatchLabels: convertLabels("app=nginx"),
            },
            FieldSelector: metav1.LabelSelector{
                MatchLabels: convertLabels("status.phase=Running"),
            },
            Syscalls: []string{"execve", "openat", "connect", "accept4"},
        },
        Status: v1alpha1.TraceStatus{
            JobID: "trace1-monitor-nginx",
        },
    }
```

This trace will monitor the syscalls `execve`, `openat`, `connect`, and `accept4` on any container living in the `swoll-hub-test` Kubernetes namespace with the label `app=nginx`.

```go
    trace2 := &v1alpha1.Trace{
        ObjectMeta: metav1.ObjectMeta{
            Namespace: "",
        },
        Spec: v1alpha1.TraceSpec{
            FieldSelector: metav1.LabelSelector{
                MatchLabels: convertLabels("status.phase=Running"),
            },
            Syscalls: []string{"execve"},
        },
        Status: v1alpha1.TraceStatus{
            JobID: "trace2-monitor-execve",
        },
    }
```

While this trace will monitor the syscall `execve` on any container in any Kubernetes namespace.

### Run & Read

```go
    go hub.RunTrace(ctx, trace1)
    go hub.RunTrace(ctx, trace2)
```

Submit these two traces to be run on the Hub as a background task.

```go
    dumpEvent := func(traceName string, ev *event.TraceEvent) {
        fmt.Printf("job-id:%s - %s: [%s/%v] (%s) %s(", traceName,
            ev.Container.FQDN(), ev.Comm, ev.Pid, ev.Error,
            ev.Argv.CallName(),
        )
        for _, arg := range ev.Argv.Arguments() {
            fmt.Printf("(%s)%s=%v ", arg.Type, arg.Name, arg.Value)
        }   
        fmt.Println(")")
    }

    hub.AttachTrace(trace1, dumpEvent)
    hub.AttachTrace(trace2, dumpEvent)
    <-ctx.Done()
```

This attaches to the running traces, and for each matched event, execute the callback `dumpEvent` until the program terminates.

### Deploy the probe into Kubernetes

#### Build the Project:

1. Modify the `Makefile` and change the `REGISTRY`, and `USERNAME` for storing your container image.
2. Modify `deploy.yaml`'s `image` configuration directive.
3. Build it.
```
$ make all
$ make push
$ make deploy
```

### Understanding the Output
If all goes according to plan, you should start seeing traffic on the deployment.

```
job-id:trace1-monitor-nginx - indexwriter.nginx-reader-writer.swoll-hub-test: [sh/2007494] (OK) execve((const char *)filename=/bin/date, (char * const)argv[]="")
job-id:trace2-monitor-execve - indexwriter.nginx-reader-writer.swoll-hub-test: [sh/2007494] (OK) execve((const char *)filename=/bin/date, (char * const)argv[]="")
job-id:trace1-monitor-nginx - indexwriter.nginx-reader-writer.swoll-hub-test: [date/2007494] (OK) openat((int)dirfd=AT_FDCWD (const char *)pathname=/etc/ld.so.cache, (int)flags=O_CLOEXEC)
job-id:trace1-monitor-nginx - indexwriter.nginx-reader-writer.swoll-hub-test: [date/2007494] (OK) openat((int)dirfd=AT_FDCWD (const char *)pathname=/lib/x86_64-linux-gnu/libc.so.6, (int)flags=O_CLOEXEC)
job-id:trace1-monitor-nginx - indexwriter.nginx-reader-writer.swoll-hub-test: [date/2007494] (OK) openat((int)dirfd=AT_FDCWD (const char *)pathname=/etc/localtime, (int)flags=O_CLOEXEC)
job-id:trace1-monitor-nginx - indexwriter.nginx-reader-writer.swoll-hub-test: [sh/2007495] (OK) execve((const char *)filename=/bin/sleep, (char * const)argv[]=5 KUBERNETES_SERVICE_PORT=443)
job-id:trace2-monitor-execve - indexwriter.nginx-reader-writer.swoll-hub-test: [sh/2007495] (OK) execve((const char *)filename=/bin/sleep, (char * const)argv[]=5 KUBERNETES_SERVICE_PORT=443)
```

Some things to note: `execve` calls are duplicated across both rules `trace1-monitor-nginx` and `trace2-monitor-execve`. This is a feature! Rules are never duplicated at the kernel side, and if an event matches two rules, only one kernel-filter is created, and the events are routed internally to different outputs.

If you were to delete the job `trace2-monitor-execve`, only the output queue is removed, the filters for `execve` stay in place until `trace1-monitor-nginx` is deleted.
