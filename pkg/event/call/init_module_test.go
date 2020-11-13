package call

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestInitModule(t *testing.T) {

	s := &InitModule{
		Name:   "drm",
		Len:    491520,
		Params: "edid_firmware='1'",
	}

	j, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}

	var i InitModule
	if err = json.Unmarshal(j, &i); err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(s.Arguments(), i.Arguments()) {
		t.Errorf("Was expecting %v, but got %v\n", s.Arguments(), i.Arguments())
	}
}
