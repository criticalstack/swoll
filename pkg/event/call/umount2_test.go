package call

import (
	"encoding/json"
	"reflect"
	"syscall"
	"testing"
)

func TestUmount2(t *testing.T) {
	s := &Umount2{
		Target: "/dev/hda2",
		Flags:  syscall.MNT_FORCE,
	}

	j, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}

	var u Umount2
	if err := json.Unmarshal(j, &u); err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(s.Arguments(), u.Arguments()) {
		t.Errorf("Was expecting %v, but got %v\n", s.Arguments(), u.Arguments())
	}

}
