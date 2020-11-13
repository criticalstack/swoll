package call

import (
	"encoding/json"
	"reflect"
	"syscall"
	"testing"
	"unsafe"

	"github.com/criticalstack/swoll/pkg/types"
)

func htons(port uint16) uint16 {
	var (
		lowbyte  uint8  = uint8(port)
		highbyte uint8  = uint8(port << 8)
		ret      uint16 = uint16(lowbyte)<<8 + uint16(highbyte)
	)
	return ret
}

func TestAcceptMarshal(t *testing.T) {
}

func TestAccept4Marshal(t *testing.T) {
	sa := &syscall.RawSockaddrInet4{
		Family: syscall.AF_INET,
		Addr:   [4]byte{172, 19, 31, 254},
		Port:   htons(80),
	}

	s := &Accept4{
		FD:    1,
		Saddr: (*types.SockAddr)(unsafe.Pointer(sa)),
		Flags: syscall.SOCK_CLOEXEC | syscall.SOCK_NONBLOCK,
	}

	j, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}

	var a4 Accept4
	if err := json.Unmarshal(j, &a4); err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(s.Arguments(), a4.Arguments()) {
		t.Errorf("Was expecting %v but got %v\n", s.Arguments(), a4.Arguments())
	}

}
