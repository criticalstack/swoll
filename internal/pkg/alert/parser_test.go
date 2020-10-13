package alert

import (
	"fmt"
	"strings"
	"testing"
)

func TestPrometheusAlertParser(t *testing.T) {
	input := `
{
	"alerts":[
		{
			"status":"firing",
			"labels":{
				"alertname":"a1",
				"container":"c1",
				"namespace":"n1",
				"pod":"p1",
				"syscall":"sys_connect"
			},
			"fingerprint":"f5dd88504b52de0a"
		},
		{
			"status":"firing",
			"labels":{
				"alertname":"a1",
				"container":"c1",
				"namespace":"n1",
				"pod":"p1",
				"syscall":"sys_execve"
			},
			"fingerprint":"8c19e2515f784e90"
		}
	]
}
`
	wantData := []*Alert{
		{
			Info: Info{
				Status:  StatusFiring,
				Name:    "a1",
				Hash:    "f5dd88504b52de0a",
				Syscall: "sys_connect",
			},
			Source: Source{
				Namespace: "n1",
				Pod:       "p1",
				Container: "c1",
			},
		},
		{
			Info: Info{
				Status:  StatusFiring,
				Name:    "a1",
				Hash:    "8c19e2515f784e90",
				Syscall: "sys_execve",
			},
			Source: Source{
				Namespace: "n1",
				Pod:       "p1",
				Container: "c1",
			},
		},
	}

	alerts, err := ParseAlerts(new(Prometheus), strings.NewReader(input))
	if err != nil {
		t.Error(err)
	}

	if alerts == nil {
		t.Errorf("could not parse alerts")
	}

	if len(alerts) != len(wantData) {
		t.Error("len(want) != len(have)")
	}

	for idx, w := range wantData {
		want := w
		have := alerts[idx]

		if want.Info != have.Info {
			t.Errorf("want %v, have %v", want.Info, have.Info)
		}

		if want.Source != have.Source {
			t.Errorf("want %v, have %v", want.Source, have.Source)
		}
	}

	fmt.Println(alerts)
}
