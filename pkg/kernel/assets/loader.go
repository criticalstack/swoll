package assets

import (
	"bytes"
)

const (
	defaultBPFObject = "internal/bpf/probe.o"
)

func LoadBPFReader() *bytes.Reader {
	return bytes.NewReader(LoadBPF())
}

func LoadBPF() []byte {
	bpf, _ := Asset(defaultBPFObject)
	return bpf
}
