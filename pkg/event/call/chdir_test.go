package call

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestChdir(t *testing.T) {
	s := &Chdir{
		Filename: "/var/log",
	}

	j, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}

	var c Chdir

	if err := json.Unmarshal(j, &c); err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(s.Arguments(), c.Arguments()) {
		t.Errorf("Was expecting %v, but got %v\n", s.Arguments(), c.Arguments())
	}
}
