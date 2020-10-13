package call

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestFutex(t *testing.T) {
	s := &Futex{
		Uaddr: 0x4323940,
		Op:    0,
		Val:   45,
	}

	j, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}

	var w Write
	if err = json.Unmarshal(j, &w); err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(s.Arguments(), w.Arguments()) {
		t.Errorf("Was expecting %v, but got %v\n", s.Arguments(), w.Arguments())
	}

}
