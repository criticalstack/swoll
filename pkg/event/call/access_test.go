package call

import (
	"encoding/json"
	"reflect"
	"testing"

	"golang.org/x/sys/unix"
)

func TestAccess(t *testing.T) {
	s := &Access{
		Pathname: "/var/log/messages",
		Mode:     unix.W_OK | unix.X_OK,
	}

	j, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}

	var a Access
	if err := json.Unmarshal(j, &a); err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(s.Arguments(), a.Arguments()) {
		t.Errorf("Was expecting %v but got %v\n", s.Arguments(), a.Arguments())
	}

}
