package call

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestRename(t *testing.T) {
	s := &Rename{
		OldName: "/tmp/master.o",
		NewName: "/tmp/kop.o",
	}
	j, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}

	var a Rename
	if err = json.Unmarshal(j, &a); err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(s.Arguments(), a.Arguments()) {
		t.Errorf("Was expecting %v, but got %v\n", s.Arguments(), a.Arguments())
	}
}
