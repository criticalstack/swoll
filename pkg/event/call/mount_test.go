package call

import (
	"encoding/json"
	"reflect"
	"syscall"
	"testing"
)

func TestMount(t *testing.T) {
	s := &Mount{
		Device:    "ext4",
		Directory: "/home",
		Type:      "tmpfs",
		Flags:     syscall.MS_SLAVE | syscall.MSG_SYN,
	}

	j, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}

	var m Mount
	if err = json.Unmarshal(j, &m); err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(s.Arguments(), m.Arguments()) {
		t.Errorf("Was expecting %v, but got %v\n", s.Arguments(), m.Arguments())
	}
}
