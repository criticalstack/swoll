package call

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/criticalstack/swoll/pkg/types"
)

func TestFtruncate(t *testing.T) {
	s := &Ftruncate{
		FD:     types.InputFD(456),
		Length: 556657,
	}

	j, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}

	var f Ftruncate
	if err = json.Unmarshal(j, &f); err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(s.Arguments(), f.Arguments()) {
		t.Errorf("Was expecting %v, but got %v\n", s.Arguments(), f.Arguments())
	}
}
