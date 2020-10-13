package call

import (
	"unsafe"

	"github.com/criticalstack/swoll/pkg/types"
)

type Write struct {
	FD    types.InputFD `json:"fd"`
	Buf   types.Buffer  `json:"buf"`
	Count int           `json:"count"`
}

func (w *Write) CallName() string  { return "write" }
func (w *Write) Return() *Argument { return &Argument{"count", "ssize_t", w.Count} }
func (w *Write) DecodeArguments(data []*byte, arglen int) error {
	w.FD = types.InputFD(types.MakeC32(unsafe.Pointer(data[0])))
	w.Count = int(types.MakeC64(unsafe.Pointer(data[2])))

	var blen int

	if w.Count > arglen {
		blen = arglen
	} else {
		blen = w.Count
	}

	w.Buf = types.Buffer(types.MakeCBytes(unsafe.Pointer(data[1]), blen))

	return nil
}

func (w *Write) Arguments() Arguments {
	return Arguments{
		{"fd", "int", w.FD},
		{"buf", "const void *", w.Buf},
		{"count", "ssize_t", w.Count},
	}
}
