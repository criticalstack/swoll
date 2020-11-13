package call

import (
	"encoding/json"
	"reflect"
	"syscall"
	"testing"
)

func TestSetns(t *testing.T) {

	s := &Setns{
		FD:     3478,
		NSType: syscall.CLONE_NEWPID | syscall.CLONE_NEWNS,
	}
	j, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}

	var a Setns
	if err = json.Unmarshal(j, &a); err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(s.Arguments(), a.Arguments()) {
		t.Errorf("Was expecting %v, but got %v\n", s.Arguments(), a.Arguments())
	}
}
