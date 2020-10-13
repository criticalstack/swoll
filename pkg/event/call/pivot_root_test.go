package call

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestPivotroot(t *testing.T) {
	s := &PivotRoot{
		NewRoot: "/tmp/newroot",
		OldRoot: "/mp/oldroot",
	}
	j, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}

	var a PivotRoot
	if err = json.Unmarshal(j, &a); err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(s.Arguments(), a.Arguments()) {
		t.Errorf("Was expecting %v, but got %v\n", s.Arguments(), a.Arguments())
	}
}
