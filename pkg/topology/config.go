package topology

const (
	// The prefix for where job-specific events are sent
	swJobStream = "job"
	// The prefix for where non-job-specific events (pathed) are sent
	swNsStream = "ns"
)

/*
type Config struct {
	// If the base file-system being monitored is on a different mount, specify
	// that here.
	AltRoot string
	// The kube CRI socket needed for resolving kernel namespaces to containers
	CRIEndpoint string
	// If running out-of-cluster, this is the local k8s configuration
	K8SEndpoint string
	// The namespace in which to monitor for pods, if empty we watch all
	// namespaces.
	K8SNamespace string
	// The raw BPF probe object loaded via assets (go-bindata) or via file
	BPFObject bytes.Reader
}
*/
