package call

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestKill(t *testing.T) {
	s := &Kill{
		Pid: 209,
		Sig: 57,
	}

	j, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}

	var k Kill
	if err = json.Unmarshal(j, &k); err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(s.Arguments(), k.Arguments()) {
		t.Errorf("was expecting %v, but got %v\n", s.Arguments(), k.Arguments())
	}

}
