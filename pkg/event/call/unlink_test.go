package call

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestUnlink(t *testing.T) {
	s := &Unlink{
		Pathname: "/tmp/unlink.txt",
	}

	j, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}

	var u Unlink
	if err := json.Unmarshal(j, &u); err != nil {
		t.Fatal(err)
	}

	//fmt.Println(string(j), u.Arguments())
	if !reflect.DeepEqual(s.Arguments(), u.Arguments()) {
		t.Errorf("Was expecting %v, but got %v\n", s.Arguments(), u.Arguments())
	}

}
