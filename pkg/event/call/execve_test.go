package call

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestExecve(t *testing.T) {
	s := &Execve{
		Filename: "/bin/swoll",
		Argv:     [4]string{"arg1", "arg2", "arg3", "arg4"},
	}

	j, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}

	var e Execve
	if err := json.Unmarshal(j, &e); err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(s.Arguments(), e.Arguments()) {
		t.Errorf("Was expecting %v, but got this %v\n", s.Arguments(), e.Arguments())
	}

}
