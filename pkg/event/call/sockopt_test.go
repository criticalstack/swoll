package call

import (
	"reflect"
	"testing"

	"github.com/criticalstack/swoll/pkg/types"

	"encoding/json"
)

func TestSockopt(t *testing.T) {
	sockN := &SockoptName{
		Tp: 1,
		Lv: 1,
	}

	s := &Sockopt{
		FD:    types.InputFD(2),
		Level: SockoptLevel(1),
		Name:  sockN,
		Val:   []byte("sock"),
		Len:   4578,
	}

	j, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}

	var a Sockopt
	if err = json.Unmarshal(j, &a); err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(s.Arguments(), a.Arguments()) {
		t.Errorf("Was expecting %v, but got %v\n", s.Arguments(), a.Arguments())
	}
}
