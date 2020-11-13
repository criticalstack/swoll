package call

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestSetuid(t *testing.T) {
	s := &Setuid{
		UID: 5,
	}
	j, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}

	var a Setuid
	if err := json.Unmarshal(j, &a); err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(s.Arguments(), a.Arguments()) {
		t.Errorf("Was expecting %v, but got %v\n", s.Arguments(), a.Arguments())
	}
}
