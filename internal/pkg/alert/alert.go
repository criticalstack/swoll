package alert

const (
	// StatusUnknown is status of this alert is unknown
	StatusUnknown = iota
	//StatusFiring is the status of this alert is currently firing
	StatusFiring
	// StatusResolved is the status of this alert has been resovled
	StatusResolved
)

// Source contains all the relevant information about an entity that triggered
// this alert.
type Source struct {
	Namespace string // the k8s namespace
	Pod       string // the k8s pod name
	Container string // the name of the k8s container
}

// Status is a reference to the state of which this alert is currently in.
type Status int

// Info contains specific information about an alert as it pertains to an AlertSource
type Info struct {
	Status  Status // unknown|firing|resolved
	Name    string // Name of the alert
	Hash    string // A unique identifier for this specific alert
	Syscall string // the name of the syscall that triggered the alert.
	URL     string // GeneratorURL
}

// Alert contains both informational fields, and the source of
// an alert.
type Alert struct {
	Info   Info
	Source Source
}
