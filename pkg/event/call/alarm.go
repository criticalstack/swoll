package call

import (
	"unsafe"

	"github.com/criticalstack/swoll/pkg/types"
)

type Alarm struct {
	Seconds uint32 `json:"seconds"`
}

func (a *Alarm) CallName() string  { return "alarm" }
func (a *Alarm) Return() *Argument { return nil }
func (a *Alarm) DecodeArguments(data []*byte, arglen int) error {
	a.Seconds = types.MakeCU32(unsafe.Pointer(data[0]))
	return nil
}

func (a *Alarm) Arguments() Arguments {
	return Arguments{
		{"seconds", "unsigned int", a.Seconds},
	}
}
