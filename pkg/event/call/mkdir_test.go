package call

import (
	"reflect"
	"testing"

	"encoding/json"

	"golang.org/x/sys/unix"
)

func TestMkdir(t *testing.T) {
	s := &Mkdir{
		Pathname: "/usr/local/bpf",
		Mode:     unix.S_ISVTX,
	}

	j, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}

	var m Mkdir
	if err = json.Unmarshal(j, &m); err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(s.Arguments(), m.Arguments()) {
		t.Errorf("Was expecting %v, but got %v\n", s.Arguments(), m.Arguments())
	}
}
