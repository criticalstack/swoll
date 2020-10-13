package call

import (
	"encoding/json"
	"reflect"
	"testing"

	"golang.org/x/sys/unix"
)

func TestMprotect(t *testing.T) {
	s := &Mprotect{
		Addr:     0x02000000,
		Len:      256,
		Prot:     unix.PROT_READ,
		AddrData: []byte("DADTDADFADSDF=="),
	}

	j, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}

	var m Mprotect
	if err = json.Unmarshal(j, &m); err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(s.Arguments(), m.Arguments()) {
		t.Errorf("Was expecting %v, but got %v\n", s.Arguments(), m.Arguments())
	}
}
