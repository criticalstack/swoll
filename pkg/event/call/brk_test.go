package call

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestBrk(t *testing.T) {
	s := &Brk{
		Addr: 0x02000000,
	}

	j, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}

	var b Brk

	if err := json.Unmarshal(j, &b); err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(s.Arguments(), b.Arguments()) {
		t.Errorf("Was expecting this is %v, but got %v", s.Arguments(), b.Arguments())
	}
}
