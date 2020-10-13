package call

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestRmdir(t *testing.T) {
	s := &Rmdir{
		Pathname: "/tmp/output.log",
	}
	j, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}

	var a Rmdir
	if err = json.Unmarshal(j, &a); err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(s.Arguments(), a.Arguments()) {
		t.Errorf("Was expecting %v, but got %v\n", s.Arguments(), a.Arguments())
	}
}
