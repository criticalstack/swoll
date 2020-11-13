package call

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/criticalstack/swoll/pkg/types"
)

func TestReadlinkat(t *testing.T) {
	s := &Readlinkat{
		DirFD:    754,
		Pathname: "var/sys/block/dm-0",
		Buf:      (types.Buffer)([]byte("readlink works")),
		Bufsize:  15,
	}

	j, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}

	var a Readlinkat
	if err = json.Unmarshal(j, &a); err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(s.Arguments(), a.Arguments()) {
		t.Errorf("Was expecting %v, but got %v\n", s.Arguments(), a.Arguments())
	}
}
