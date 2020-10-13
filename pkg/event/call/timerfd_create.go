package call

import (
	"unsafe"

	"github.com/criticalstack/swoll/pkg/types"
)

type TimerFDCreate struct {
	Clock types.TFDClock   `json:"clock"`
	Flags types.TimerFlags `json:"flags"`
}

func (t *TimerFDCreate) CallName() string  { return "timerfd_create" }
func (t *TimerFDCreate) Return() *Argument { return nil }
func (t *TimerFDCreate) DecodeArguments(data []*byte, arglen int) error {
	t.Clock = types.TFDClock(types.MakeC32(unsafe.Pointer(data[0])))
	t.Flags = types.TimerFlags(types.MakeC32(unsafe.Pointer(data[1])))
	return nil
}

func (t *TimerFDCreate) Arguments() Arguments {
	return Arguments{
		{"clockid", "int", t.Clock},
		{"flags", "int", t.Flags},
	}
}
