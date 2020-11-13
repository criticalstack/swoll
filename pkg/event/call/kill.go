package call

import (
	"unsafe"

	"github.com/criticalstack/swoll/pkg/types"
)

type Kill struct {
	Pid int32 `json:"pid"`
	Sig int32 `json:"sig"`
}

func (k *Kill) CallName() string  { return "kill" }
func (k *Kill) Return() *Argument { return nil }
func (k *Kill) DecodeArguments(data []*byte, arglen int) error {
	k.Pid = types.MakeC32(unsafe.Pointer(data[0]))
	k.Sig = types.MakeC32(unsafe.Pointer(data[1]))

	return nil
}

func (k *Kill) Arguments() Arguments {
	return Arguments{
		{"pid", "pid_t", k.Pid},
		{"sig", "int", k.Sig},
	}
}
