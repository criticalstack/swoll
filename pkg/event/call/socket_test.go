package call

import (
	"encoding/json"
	"reflect"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestSocket(t *testing.T) {
	s := &Socket{
		Family:   SockFamily(syscall.AF_INET),
		Type:     SockType(unix.SOCK_STREAM),
		Protocol: SockProtocol(0),
	}

	j, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}

	var a Socket

	if err := json.Unmarshal(j, &a); err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(s.Arguments(), a.Arguments()) {
		t.Errorf("Was expecting %v but got %v\n", s.Arguments(), a.Arguments())
	}
}
