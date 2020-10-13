package call

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestGetcwd(t *testing.T) {
	s := &Getcwd{
		Buf:  "/tmp",
		Size: 5,
	}

	j, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}

	var g Getcwd
	if err = json.Unmarshal(j, &g); err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(s.Arguments(), g.Arguments()) {
		t.Errorf("Was expecting %v, but got %v\n", s.Arguments(), g.Arguments())
	}

}
