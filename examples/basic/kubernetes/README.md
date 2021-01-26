# What

A simple application which uses the Swoll API to trace system calls on a
kubernetes cluster. If a kernel event was associated with a host inside
kuberentes, that information will be displayed.

If an event did not come from kubernetes, (e.g., local operations) it will be
marked with "-.-.-".

# building

1. Modify `Makefile` and change the docker repo info.
2. Modify `deploy.yaml`'s `image` to the repository you created
3. Run:

```
make all
make push
make deploy
```

