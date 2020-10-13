package call

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestLink(t *testing.T) {
	s := &Link{
		OldName: "/var/tmp/systmd-private",
		NewName: "/tmp/systemd-read",
	}

	j, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}

	var l Link
	if err = json.Unmarshal(j, &l); err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(s.Arguments(), l.Arguments()) {
		t.Errorf("Was expecting %v, but got %v\n", s.Arguments(), l.Arguments())
	}
}
