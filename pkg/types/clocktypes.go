package types

import (
	"encoding/json"
	"strings"

	"golang.org/x/sys/unix"
)

type TFDClock int
type TimerFlags int

const (
	TFD_CLOEXEC             = unix.O_CLOEXEC
	TFD_NONBLOCK            = unix.O_NONBLOCK
	TFD_TIMER_ABSTIME       = 1 << 0
	TFD_TIMER_CANCEL_ON_SET = 1 << 1
)

var setTimerFlags = map[int]string{
	TFD_CLOEXEC:             "TFD_CLOEXEC",
	TFD_NONBLOCK:            "TFD_NONBLOCK",
	TFD_TIMER_ABSTIME:       "TFD_TIMER_ABSTIME",
	TFD_TIMER_CANCEL_ON_SET: "TFD_TIMER_CANCEL_ON_SET",
}

/*
var clockTypes = map[int]string{
	unix.CLOCK_REALTIME:       "CLOCK_REALTIME",
	unix.CLOCK_MONOTONIC:      "CLOCK_MONOTONIC",
	unix.CLOCK_BOOTTIME:       "CLOCK_BOOTTIME",
	unix.CLOCK_REALTIME_ALARM: "CLOCK_REALTIME_ALARM",
	unix.CLOCK_BOOTTIME_ALARM: "CLOCK_BOOTTIME_ALARM",
}
*/

type Timespec struct {
	Sec  int64
	Nsec int64
}

type Itimerspec struct {
	Interval Timespec
	Value    Timespec
}

func (f TimerFlags) Parse() []string {
	ret := make([]string, 0)
	fint := int(f)

	for mode, fstr := range setTimerFlags {
		if fint&mode != 0 {
			ret = append(ret, fstr)
		}
	}

	return ret
}

func (f TimerFlags) String() string {
	return strings.Join(f.Parse(), "|")
}

func (f TimerFlags) MarshalJSON() ([]byte, error) {
	return json.Marshal(f.Parse())
}

func (f *TimerFlags) UnmarshalJSON(data []byte) error {
	var a []string

	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}

	for _, val := range a {
		switch val {
		case "TFD_CLOEXEC":
			*f |= TFD_CLOEXEC
		case "TFD_NONBLOCK":
			*f |= TFD_NONBLOCK
		case "TFD_TIMER_ABSTIME":
			*f |= TFD_TIMER_ABSTIME
		case "TFD_TIMER_CANCEL_ON_SET":
			*f |= TFD_TIMER_CANCEL_ON_SET
		}
	}

	return nil
}
