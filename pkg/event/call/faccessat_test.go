package call

import (
	"encoding/json"
	"reflect"
	"testing"

	"golang.org/x/sys/unix"
)

func TestFaccessat(t *testing.T) {
	s := &Faccessat{
		FD:       -100,
		Pathname: "/var/log/dmesg",
		Mode:     0777,
		Flags:    unix.AT_SYMLINK_NOFOLLOW,
	}

	j, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}

	var f Faccessat
	if err := json.Unmarshal(j, &f); err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(s.Arguments(), f.Arguments()) {
		t.Errorf("Was expecting %v, but got %v\n", s.Arguments(), f.Arguments())
	}

}
