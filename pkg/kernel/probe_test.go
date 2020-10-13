package kernel

import (
	"bytes"
	"io/ioutil"
	"testing"
)

func TestProbe(t *testing.T) {
	bpf, err := ioutil.ReadFile("fixtures/dummy_probe.o")
	if err != nil {
		t.Error(err)
	}

	p, err := NewProbe(bytes.NewReader(bpf), nil)
	if err != nil {
		t.Error(err)
	}
	_ = p
}
