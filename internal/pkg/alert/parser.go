package alert

import "io"

// Parser is an abstraction interface around parsing raw alert data.
type Parser interface {
	ParseAlerts(r io.Reader) ([]*Alert, error)
}

// ParseAlerts runs the parser `p` against the data in `r`
func ParseAlerts(p Parser, r io.Reader) ([]*Alert, error) {
	return p.ParseAlerts(r)
}
