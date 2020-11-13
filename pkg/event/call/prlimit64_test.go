package call

import (
	"encoding/json"
	"reflect"
	"syscall"
	"testing"
)

func TestPrlimit64(t *testing.T) {
	s := &Prlimit64{
		Pid:      40623,
		Resource: syscall.RLIMIT_CPU,
		New: (Rlimit)(syscall.Rlimit{
			Cur: 39,
			Max: 40004,
		}),
		Old: (Rlimit)(syscall.Rlimit{
			Cur: 394,
			Max: 45637,
		}),
	}

	j, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}

	var a Prlimit64
	if err = json.Unmarshal(j, &a); err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(s.Arguments(), a.Arguments()) {
		t.Errorf("Was expecting %v, but got %v\n", s.Arguments(), a.Arguments())
	}
}
