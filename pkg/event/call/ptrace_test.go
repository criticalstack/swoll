package call

import (
	"encoding/json"
	"reflect"
	"syscall"
	"testing"
)

func TestPtrace(t *testing.T) {
	s := &Ptrace{
		Request: syscall.PTRACE_CONT,
		PID:     45678,
		Addr:    0x500000,
		Data:    PtraceData(23),
	}
	j, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}

	var a Ptrace
	if err = json.Unmarshal(j, &a); err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(s.Arguments(), a.Arguments()) {
		t.Errorf("Was expecting %v, but got %v\n", s.Arguments(), a.Arguments())
	}
}
