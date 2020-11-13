package call

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestClose(t *testing.T) {
	s := &Close{
		FD: 1,
	}

	j, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	var c Close
	if err := json.Unmarshal(j, &c); err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(s.Arguments(), c.Arguments()) {
		t.Errorf("Was expecting %v, but got %v\n", s.Arguments(), c.Arguments())
	}
}
