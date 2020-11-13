package call

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/criticalstack/swoll/pkg/types"
)

func TestListen(t *testing.T) {
	s := &Listen{
		Sock:    types.InputFD(48),
		Backlog: 5,
	}

	j, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}

	var l Listen
	if err = json.Unmarshal(j, &l); err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(s.Arguments(), l.Arguments()) {
		t.Errorf("Was expecting %v, but got %v\n", s.Arguments(), l.Arguments())
	}

}
