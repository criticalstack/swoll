package call

import (
	"encoding/json"
	"reflect"
	"syscall"
	"testing"

	"github.com/criticalstack/swoll/pkg/types"
)

func TestRecvfrom(t *testing.T) {
	s := &Recvfrom{
		FD:    types.InputFD(55),
		Ubuf:  types.Buffer([]byte("core dump")),
		Size:  10,
		OSize: 11,
		Flags: (types.MsgFlags)(syscall.MSG_PEEK | syscall.MSG_OOB),
	}

	j, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}

	var a Recvfrom
	if err = json.Unmarshal(j, &a); err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(s.Arguments(), a.Arguments()) {
		t.Errorf("Was expecting %v, but got %v\n", s.Arguments(), a.Arguments())
	}
}
