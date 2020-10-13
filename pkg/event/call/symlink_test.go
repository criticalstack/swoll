package call

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestSymlink(t *testing.T) {
	s := &Symlink{
		Target:   "/tmp/socket_link",
		Linkpath: "/usr/app/socket_link",
	}

	j, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}

	var a Symlink

	if err := json.Unmarshal(j, &a); err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(s.Arguments(), a.Arguments()) {
		t.Errorf("Was expecting %v, but got %v\n", s.Arguments(), a.Arguments())
	}
}
