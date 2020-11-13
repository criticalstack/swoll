package call

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestExit(t *testing.T) {
	s := &Exit{
		Code: 1,
	}

	j, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}

	var e Exit
	if err := json.Unmarshal(j, &e); err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(s.Arguments(), e.Arguments()) {
		t.Errorf("Was expecting %v, but got %v\n", s.Arguments(), e.Arguments())
	}

}
