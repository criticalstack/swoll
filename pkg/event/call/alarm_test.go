package call

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestAlarm(t *testing.T) {
	s := &Alarm{
		Seconds: 10,
	}

	j, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}

	var a Alarm

	if err := json.Unmarshal(j, &a); err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(s.Arguments(), a.Arguments()) {
		t.Errorf("Was expecting %v but got %v\n", s.Arguments(), a.Arguments())
	}

}
