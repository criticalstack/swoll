package call

import (
	"unsafe"

	"github.com/criticalstack/swoll/pkg/types"
)

type Ftruncate struct {
	FD     types.InputFD `json:"fd"`
	Length int           `json:"length"`
}

func (f *Ftruncate) CallName() string  { return "ftruncate" }
func (f *Ftruncate) Return() *Argument { return nil }
func (f *Ftruncate) DecodeArguments(data []*byte, arglen int) error {
	f.FD = types.InputFD(types.MakeC32(unsafe.Pointer(data[0])))
	f.Length = int(types.MakeC32(unsafe.Pointer(data[1])))

	return nil
}

func (f *Ftruncate) Arguments() Arguments {
	return Arguments{
		{"fd", "int", f.FD},
		{"length", "off_t", f.Length},
	}
}
