package call

import (
	"encoding/json"
	"reflect"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestGetSockopt(t *testing.T) {
	s := &Getsockopt{
		Sockopt: Sockopt{
			FD:    1,
			Level: SockoptLevel(int(syscall.SOL_SOCKET)),
			Name: &SockoptName{
				Tp: unix.SO_REUSEPORT,
				Lv: syscall.SOL_SOCKET,
			},
			Val: []byte{1, 0, 0, 0},
			Len: 1,
		},
	}

	j, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}

	var a Getsockopt
	if err := json.Unmarshal(j, &a); err != nil {
		t.Error(err)
	}
	if !reflect.DeepEqual(s.Arguments(), a.Arguments()) {
		t.Errorf("Was expecting %v, but got %v\n", s.Arguments(), a.Arguments())
	}
}
