[![Build Status](https://drone.cstack.co/api/badges/criticalstack/swoll/status.svg)](https://drone.cstack.co/criticalstack/swoll)

![logo](media/logo.png) 

# Introduction

Swoll is an experimental suite of applications and APIs for monitoring kernel-level activity on a
kubernetes cluster; most of which is written in the Golang programming language, strewn about with 
bits and bobs of C and Yaml. 

Using simple counters and minimal state, Swoll has the ability to report on a
wide bevy of information pertaining to system calls being made by or from a
container running inside a Kubernetes cluster. Each individual metric for both
timing and counting contains the following information:

* Syscall
  - Return Status
  - Classification
  - Group
* Kubernetes information
  - Namespace
  - Pod
  - Container

Since data is aggregated in this manner, every call, every error, for every
container, running in every pod is accounted for. One can query for the count of
calls to the function `openat` made by a container in the pod `coredns`, within the 
`kube-system` namespace which resulted in a "No such file or directory" error (ENOENT).

By default, this data is exported in `Prometheus` format on each running
instance at the URI `/metrics`. More detailed chart examples (powered by
echarts) can be seen at the URI `/metrics/charts`.


**Example charts output**
![Charts](media/charts-ss.png)
_The above Sankey diagram displays the distribution of system calls in an interesting™ manner._


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
_Total count of syscalls grouped by the return-status originating from the kubernetes namespace `kube-system`_

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
_Count all calls to the function `sys_openat` grouped by kubernetes Pod, and Namespace_

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
_Query the relative change in the rate of calls that incurred an error compared to the previous 5 minutes grouped by container, pod, namespace, and syscall_ 



While metrics by themselves are great and all, `swoll` also provides a
kubernetes-native interface for creating, collecting, and presenting detailed
realtime logs of system activity. 



## swoll-trace
## swoll-server
## swoll-controller
## swoll-client

*Monitor. Consume. React.*

Kernel
  - filtering
  - collection
  - distribution
  - metrics
Userland
  - collection
  - translation
  - presentation


# Installation

See [BUILD INSTRUCTIONS](BUILDING.md)

# Usage

TODO

## Contributing
Any contributors must accept and [sign the CLA](https://cla-assistant.io/criticalstack/swoll).
This project has adopted the [Capital One Open Source Code of conduct](https://developer.capitalone.com/resources/code-of-conduct).
