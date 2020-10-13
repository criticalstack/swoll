package call

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestChroot(t *testing.T) {
	s := &Chroot{
		Filename: "/root",
	}

	j, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}

	var c Chroot

	if err := json.Unmarshal(j, &c); err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(s.Arguments(), c.Arguments()) {
		t.Errorf("Was expecting %v, but got %v\b", s.Arguments(), c.Arguments())
	}
}
