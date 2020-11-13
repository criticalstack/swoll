package call

import (
	"encoding/json"
	"reflect"
	"syscall"
	"testing"

	"github.com/criticalstack/swoll/pkg/types"
)

func TestOpenat(t *testing.T) {

	s := &Openat{
		DirFD:    types.DirFD(3846),
		Pathname: "/tmp/output.txt",
		Flags:    syscall.O_RDWR | syscall.O_SYNC,
	}

	j, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}

	var o Openat
	if err = json.Unmarshal(j, &o); err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(s.Arguments(), o.Arguments()) {
		t.Errorf("Was expecting %v, but got %v\n", s.Arguments(), o.Arguments())
	}
}
