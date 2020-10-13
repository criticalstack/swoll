package call

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestCreat(t *testing.T) {
	s := &Creat{
		Pathname: "/var/log/messages",
		Mode:     0777,
	}

	j, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	var c Creat
	if err := json.Unmarshal(j, &c); err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(s.Arguments(), c.Arguments()) {
		t.Errorf("Was expecting %v, but got %v\n", s.Arguments(), c.Arguments())
	}

}
