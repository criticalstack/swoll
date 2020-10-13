package call

import (
	"reflect"
	"testing"

	"encoding/json"

	"github.com/criticalstack/swoll/pkg/types"
)

func TestWrite(t *testing.T) {

	s := &Write{
		FD:    types.InputFD(1),
		Buf:   types.Buffer([]byte("write test")),
		Count: 12,
	}

	j, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}

	var w Write
	if err = json.Unmarshal(j, &w); err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(s.Arguments(), w.Arguments()) {
		t.Errorf("Was expecting %v, but got %v\n", s.Arguments(), w.Arguments())
	}

}
