package call

import (
	"encoding/json"
	"reflect"
	"syscall"
	"testing"
	"unsafe"

	"github.com/criticalstack/swoll/pkg/types"
)

func TestSendto(t *testing.T) {
	sa := &syscall.RawSockaddrInet4{
		Family: syscall.AF_INET,
		Addr:   [4]byte{172, 19, 31, 254},
		Port:   htons(80),
	}

	s := &Sendto{
		FD:    types.InputFD(956),
		Ubuf:  types.Buffer([]byte("test")),
		Size:  5,
		Flags: syscall.MSG_OOB | syscall.MSG_TRUNC,
		Saddr: (*types.SockAddr)(unsafe.Pointer(sa)),
	}
	j, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}

	var w Sendto
	if err = json.Unmarshal(j, &w); err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(s.Arguments(), w.Arguments()) {
		t.Errorf("Was expecting %v, but got %v\n", s.Arguments(), w.Arguments())
	}

}
