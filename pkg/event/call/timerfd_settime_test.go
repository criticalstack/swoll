package call

import (
	"reflect"
	"testing"

	"encoding/json"

	"github.com/criticalstack/swoll/pkg/types"
	"golang.org/x/sys/unix"
)

func TestTimerFDSettime(t *testing.T) {

	n := types.Itimerspec{
		Interval: types.Timespec{
			Sec:  1250,
			Nsec: 0,
		},
		Value: types.Timespec{
			Sec:  1250,
			Nsec: 0,
		},
	}

	o := types.Itimerspec{
		Interval: types.Timespec{
			Sec:  2450,
			Nsec: 0,
		},
		Value: types.Timespec{
			Sec:  2350,
			Nsec: 0,
		},
	}

	s := &TimerFDSettime{
		FD:    types.InputFD(98),
		Flags: types.TimerFlags(unix.CLOCK_REALTIME),
		New:   n,
		Old:   o,
	}
	j, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}

	var a TimerFDSettime
	if err = json.Unmarshal(j, &a); err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(s.Arguments(), a.Arguments()) {
		t.Errorf("Was expecting %v, but got %v\n", s.Arguments(), a.Arguments())
	}
}
