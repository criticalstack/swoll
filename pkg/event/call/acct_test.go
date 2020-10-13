package call

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestAcct(t *testing.T) {
	s := &Acct{
		Pathname: "/var/log/wtmp",
	}

	j, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}

	var a Acct
	if err := json.Unmarshal(j, &a); err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(s.Arguments(), a.Arguments()) {
		t.Errorf("Was expecting %v, but got %v\n", s.Arguments(), a.Arguments())
	}

}
