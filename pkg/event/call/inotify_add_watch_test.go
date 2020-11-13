package call

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/criticalstack/swoll/pkg/types"
	"golang.org/x/sys/unix"
)

func TestINotifyAddWatch(t *testing.T) {
	s := &INotifyAddWatch{
		FD:       types.InputFD(29),
		Pathname: "/usr/unix_listen.log",
		Mask:     unix.IN_ACCESS | unix.IN_CLOSE,
	}

	j, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}

	var i INotifyAddWatch
	if err := json.Unmarshal(j, &i); err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(s.Arguments(), i.Arguments()) {
		t.Errorf("Was expecting %v, but got\n %v\n", s.Arguments(), i.Arguments())
	}
}
