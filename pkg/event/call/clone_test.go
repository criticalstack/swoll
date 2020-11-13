package call

import (
	"encoding/json"
	"reflect"
	"syscall"
	"testing"
)

func TestClone(t *testing.T) {
	s := &Clone{
		Flags:       syscall.CLONE_NEWPID | syscall.CLONE_NEWUTS,
		NewStack:    0x31337,
		ChildStack:  0x31338,
		ParentStack: 0x0,
		Tls:         0,
	}

	j, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}

	var c Clone
	if err := json.Unmarshal(j, &c); err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(s.Arguments(), c.Arguments()) {
		t.Errorf("Was expecting %v, but got %v\n", s.Arguments(), c.Arguments())
	}
}
