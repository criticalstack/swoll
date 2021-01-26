# What

A line-by-line documented example of how to use Swoll's topology and hub APIs to
manage kernel states across multiple jobs using only a single BPF context.

See: `main.go`

# building

1. Modify `Makefile` and change the docker repo info.
2. Modify `deploy.yaml`'s `image` to the repository you created
3. Run:

```
make all
make push
make deploy
```

