package call

import (
	"unsafe"

	"github.com/criticalstack/swoll/pkg/types"
)

type Read struct {
	FD    types.InputFD `json:"fd"`
	Buf   types.Buffer  `json:"buf"`
	Count int           `json:"count"`
}

func (r *Read) CallName() string  { return "read" }
func (r *Read) Return() *Argument { return &Argument{"count", "int", r.Count} }
func (r *Read) DecodeArguments(data []*byte, arglen int) error {
	r.FD = types.InputFD(types.MakeC32(unsafe.Pointer(data[0])))
	r.Count = int(types.MakeC64(unsafe.Pointer(data[2])))

	var blen int

	if r.Count > arglen {
		blen = arglen
	} else {
		blen = r.Count
	}

	r.Buf = types.Buffer(types.MakeCBytes(unsafe.Pointer(data[1]), blen))

	return nil
}

func (r *Read) Arguments() Arguments {
	return Arguments{
		{"fd", "int", r.FD},
		{"buf", "void *", r.Buf},
		{"count", "ssize_t", r.Count},
	}
}
