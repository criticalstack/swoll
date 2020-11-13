package call

import (
	"encoding/json"
	"reflect"
	"syscall"
	"testing"

	"github.com/criticalstack/swoll/pkg/types"
)

func TestOpen(t *testing.T) {

	s := Open{
		Filename: "/tmp/output.txt",
		Flags:    0,
		Mode:     syscall.S_IRUSR,
		Ret:      types.OutputFD(12),
	}

	j, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}

	var o Open
	if err = json.Unmarshal(j, &o); err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(s.Arguments(), o.Arguments()) {
		t.Errorf("Was expecting %v, but got %v\n", s.Arguments(), o.Arguments())
	}
}
