package call

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/criticalstack/swoll/pkg/types"
)

func TestRead(t *testing.T) {
	s := &Read{
		FD:    74,
		Buf:   (types.Buffer)([]byte("/tmp/virt.txt")),
		Count: 203,
	}

	j, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}

	var a Read
	if err = json.Unmarshal(j, &a); err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(s.Arguments(), a.Arguments()) {
		t.Errorf("Was expecting %v, but got %v\n", s.Arguments(), a.Arguments())
	}
}
