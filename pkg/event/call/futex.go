package call

import (
	"unsafe"

	"github.com/criticalstack/swoll/pkg/types"
)

type Futex struct {
	Uaddr uint32 `json:"uaddr"`
	Op    int    `json:"op"`
	Val   uint32 `json:"val"`
}

func (f *Futex) CallName() string  { return "futex" }
func (f *Futex) Return() *Argument { return nil }
func (f *Futex) DecodeArguments(data []*byte, arglen int) error {
	f.Uaddr = types.MakeCU32(unsafe.Pointer(data[0]))
	f.Op = int(types.MakeC32(unsafe.Pointer(data[1])))
	f.Val = types.MakeCU32(unsafe.Pointer(data[2]))
	return nil
}

func (f *Futex) Arguments() Arguments {
	return Arguments{
		{"uaddr", "int *", f.Uaddr},
		{"futex_op", "int", f.Op},
		{"val", "int", f.Val},
	}
}
