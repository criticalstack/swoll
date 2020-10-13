package call

import (
	"unsafe"

	"github.com/criticalstack/swoll/pkg/types"
)

type TimerFDSettime struct {
	FD    types.InputFD    `json:"fd"`
	Flags types.TimerFlags `json:"flags"`
	New   types.Itimerspec `json:"new"`
	Old   types.Itimerspec `json:"old"`
}

func (f *TimerFDSettime) CallName() string  { return "timerfd_settime" }
func (f *TimerFDSettime) Return() *Argument { return nil }
func (f *TimerFDSettime) DecodeArguments(data []*byte, arglen int) error {
	f.FD = types.InputFD(types.MakeC32(unsafe.Pointer(data[0])))
	f.Flags = types.TimerFlags(types.MakeC32(unsafe.Pointer(data[1])))
	f.New = *(*types.Itimerspec)(unsafe.Pointer(data[2]))
	f.Old = *(*types.Itimerspec)(unsafe.Pointer(data[3]))

	return nil
}
func (f *TimerFDSettime) Arguments() Arguments {
	return Arguments{
		{"fd", "int", f.FD},
		{"flags", "int", f.Flags},
		{"new_value", "const struct itimerspec *", f.New},
		{"old_value", "struct itimerspec *", f.Old},
	}
}
