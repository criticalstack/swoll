package hub

const (
	// The prefix for where job-specific events are sent
	swJobStream = "job"
	// The prefix for where non-job-specific events (pathed) are sent
	swNsStream = "ns"
)

type Config struct {
	// if we have an alternate root setting, and the endpoints start with
	// "$root", use the AltRoot as the CWD for any further lookups, whether
	// that be for /proc, or for configurations.
	//
	// mainly here for development reasons, if you're able to see your k8s
	// node via /proc/<pid>/root, you can set the AltRoot to this, and
	// namespace lookups will look at /proc/<pid>/root/proc/...
	// cri socket will look at /proc/<pid>/root/path/to/cri.sock
	// etc...
	AltRoot string
	// The kube CRI socket needed for resolving kernel namespaces to containers
	CRIEndpoint string
	// If running out-of-cluster, this is the local k8s configuration
	K8SEndpoint string
	// The namespace in which to monitor for pods, if empty we watch all
	// namespaces.
	K8SNamespace string
	// The raw BPF probe object loaded via assets (go-bindata) or via file
	BPFObject []byte
}
