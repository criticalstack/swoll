package call

import (
	"reflect"
	"testing"

	"encoding/json"

	"github.com/criticalstack/swoll/pkg/types"
)

func TestTimerFDCreat(t *testing.T) {
	s := &TimerFDCreate{
		Clock: types.TFDClock(45),
		Flags: types.TFD_CLOEXEC,
	}

	j, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}

	var a TimerFDCreate
	if err := json.Unmarshal(j, &a); err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(s.Arguments(), a.Arguments()) {
		t.Errorf("was expecting %v, but got %v\n", s.Arguments(), a.Arguments())
	}
}
