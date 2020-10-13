// Prometheus Alert-Manager alert parser

package alert

import (
	"encoding/json"
	"io"

	"github.com/prometheus/alertmanager/template"
	"github.com/prometheus/common/model"
)

// Prometheus is our parser for prometheus-sourced alerts
type Prometheus struct {
	Parser
}

// parseStatus converts the prometheus-alert status to our
// internal status name.
func parseStatus(in model.AlertStatus) Status {
	switch in {
	case model.AlertFiring:
		return StatusFiring
	case model.AlertResolved:
		return StatusResolved
	default:
		return StatusUnknown
	}
}

// parseSingleAlert will parse a single alert within a group
// of alerts from prometheus.
func parseSingleAlert(in template.Alert) (*Alert, error) {
	return &Alert{
		Info: Info{
			Status:  parseStatus(model.AlertStatus(in.Status)),
			Name:    in.Labels["alertname"],
			Syscall: in.Labels["syscall"],
			Hash:    in.Fingerprint,
			URL:     in.GeneratorURL,
		},
		Source: Source{
			Namespace: in.Labels["namespace"],
			Pod:       in.Labels["pod"],
			Container: in.Labels["container"],
		},
	}, nil
}

// ParseAlerts parses prometheus-formatted data from `r`
func (p *Prometheus) ParseAlerts(r io.Reader) ([]*Alert, error) {
	data := template.Data{}

	if err := json.NewDecoder(r).Decode(&data); err != nil {
		return nil, err
	}

	ret := make([]*Alert, 0)

	for _, rawAlert := range data.Alerts {
		alert, err := parseSingleAlert(rawAlert)
		if err != nil {
			return nil, err
		}

		ret = append(ret, alert)
	}

	return ret, nil
}
