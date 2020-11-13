package call

import (
	"encoding/json"
	"reflect"
	"syscall"
	"testing"
)

func TestFstat(t *testing.T) {
	s := &Fstat{
		FD: 1,
		StatBuf: &syscall.Stat_t{
			Dev: 1,
		},
	}

	j, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	var f Fstat
	if err := json.Unmarshal(j, &f); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(s.Arguments(), f.Arguments()) {
		t.Errorf("Was expecting %v, but got %v\n", s.Arguments(), f.Arguments())
	}

}
