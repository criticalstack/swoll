package call

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/criticalstack/swoll/pkg/types"
)

func TestNanosleep(t *testing.T) {
	s := &Nanosleep{
		Req: types.Timespec{
			Sec:  1250,
			Nsec: 0,
		},
		Rem: types.Timespec{
			Sec:  9954,
			Nsec: 3456,
		},
	}

	j, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}

	var n Nanosleep
	if err = json.Unmarshal(j, &n); err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(s.Arguments(), n.Arguments()) {
		t.Errorf("Was expecting %v, but got %v\n", s.Arguments(), n.Arguments())
	}
}
