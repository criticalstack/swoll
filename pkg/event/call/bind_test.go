package call

import (
	"encoding/json"
	"reflect"
	"syscall"
	"testing"
	"unsafe"

	"github.com/criticalstack/swoll/pkg/types"
)

func TestBind(t *testing.T) {
	sa := &syscall.RawSockaddrInet4{
		Family: syscall.AF_INET,
		Addr:   [4]byte{172, 19, 31, 254},
		Port:   htons(80),
	}

	s := &Bind{
		FD:    1,
		Saddr: (*types.SockAddr)(unsafe.Pointer(sa)),
	}

	j, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}

	var b Bind

	if err := json.Unmarshal(j, &b); err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(s.Arguments(), b.Arguments()) {
		t.Errorf("Was expecting %v but got %v\n", s.Arguments(), b.Arguments())
	}

}
