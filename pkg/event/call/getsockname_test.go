package call

import (
	"encoding/json"
	"reflect"
	"syscall"
	"testing"
	"unsafe"

	"github.com/criticalstack/swoll/pkg/types"
)

func TestGetsockname(t *testing.T) {

	sa := &syscall.RawSockaddrInet4{
		Family: syscall.AF_INET,
		Addr:   [4]byte{172, 19, 31, 254},
		Port:   htons(80),
	}

	s := &Getsockname{
		FD:    types.InputFD(20),
		Saddr: (*types.SockAddr)(unsafe.Pointer(sa)),
	}

	j, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}

	var g Getsockname
	if err := json.Unmarshal(j, &g); err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(s.Arguments(), g.Arguments()) {
		t.Errorf("Was expecting %v but got %v\n", s.Arguments(), g.Arguments())
	}
}
