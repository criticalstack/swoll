package call

import (
	"encoding/json"
	"reflect"
	"syscall"
	"testing"
	"unsafe"

	"github.com/criticalstack/swoll/pkg/types"
)

func TestConnect(t *testing.T) {
	sa := &syscall.RawSockaddrInet4{
		Family: syscall.AF_INET,
		Addr:   [4]byte{172, 19, 31, 254},
		Port:   htons(80),
	}

	s := &Connect{
		FD:    1,
		Saddr: (*types.SockAddr)(unsafe.Pointer(sa)),
	}

	j, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}

	var c Connect
	if err := json.Unmarshal(j, &c); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(s.Arguments(), c.Arguments()) {
		t.Errorf("Was expecting %v, but got %v\n", s.Arguments(), c.Arguments())
	}

}
