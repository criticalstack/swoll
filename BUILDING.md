# Building

**NOTE** It is suggested to have at LEAST Linux *v5.0.0* installed on your node-workers and the host in which 

## Kernel eBPF

Swoll uses a combination of C for the eBPF probe, and golang for the client. If you wish to compile the eBPF probe manually, the following packages must be installed:

* clang
* llvm
* libelf-dev
* linux-headers
* binutils (for objdump)

The eBPF object may be compiled and installed separately, and all tooling should accept a `-b <bpf object>` flag, which is the path to the local compiled eBPF object.

Then run:
```
make -C ./internal/bpf
```

## Developing locally with cinder

Development of Swoll can be done locally using [cinder](https://docs.crit.sh/cinder-guide/overview.html). It requires the swoll binary and probe object be created on the host, so first start by running `make all`.

Next, create a new cinder cluster using the provided [config.yaml](internal/deploy/config.yaml) file:

```shell
$ cinder create cluster -c internal/deploy/config.yaml
```

When finished, this will merge the kubeconfig into your `$HOME/.kube/config` file and set it as the current context. It will also create the necessary pki and perform the swoll self-test. The full log of what `cinder create cluster` is doing will be output should any of the `postCritCommands` fail, or you can add `-v` to the command to get the full output.

This makes use of the [Local Registry](https://docs.crit.sh/cinder-guide/local-registry.html) feature of cinder, so the image being referenced by the DaemonSet needs to be built and pushed to the registry:

```shell
$ docker build . -t localhost:5000/swoll:latest --build-arg GOPROXY --build-arg GOSUMDB
$ docker push localhost:5000/swoll:latest
```

The image will be available in cinder as `cinderegg:5000/swoll:latest`. Last, deploy the Kubernetes manifests:

```shell
$ kubectl apply -f internal/deploy/manifests
```

## Testing goreleaser

Running the following should produce all release artifacts (tar.gz, deb/rpm):

```shell
$ goreleaser release --rm-dist --skip-publish --skip-validate
```

## Installing the helm chart

Start a new cinder cluster just like above (don't forget to `make all`):

```shell
$ cinder create cluster -c internal/deploy/config.yaml
```

Installing the helm chart from cscr.io:

```shell
$ helm repo add criticalstack https://charts.cscr.io/criticalstack
$ kubectl create namespace swoll
$ helm install swoll criticalstack/swoll --namespace swoll
```

## Testing the CRD

Deploy the Controller:

```shell
make deploy
```

Create a trace: 

```shell
$ kubectl apply -f - << EOF
apiVersion: tools.swoll.criticalstack.com/v1alpha1
kind: Trace
metadata:
  name: monitor-cilium
spec:
  syscalls:
    - execve
    - openat
  labelSelector:
      matchLabels:
          k8s-app: cilium
  fieldSelector:
      matchLabels:
          status.phase: Running
EOF
```

And you should start seeing results:

```shell
$ kubectl logs -l sw-job=monitor-cilium -f
{"endpoint":{"hostname":"172.19.0.3","port":9095,"UseTLS":false},"payload":{"syscall":{"nr":257,"name":"sys_openat","class":"FileSystem","group":"Files"} ...
```
