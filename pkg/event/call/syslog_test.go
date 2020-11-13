package call

import (
	"reflect"
	"testing"

	"encoding/json"

	"golang.org/x/sys/unix"
)

func TestSyslog(t *testing.T) {
	s := &Syslog{
		Type: unix.SYSLOG_ACTION_OPEN,
		Buf:  "bpf kernel error",
		Len:  18,
	}

	j, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}

	var y Syslog
	if err := json.Unmarshal(j, &y); err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(s.Arguments(), y.Arguments()) {
		t.Errorf("Was expecting %v, but got %v\n", s.Arguments(), y.Arguments())
	}

}
