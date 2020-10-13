package call

import (
	"unsafe"

	"github.com/criticalstack/swoll/pkg/types"
)

type Listen struct {
	Sock    types.InputFD `json:"sock"`
	Backlog int           `json:"backlog"`
}

func (l *Listen) CallName() string  { return "listen" }
func (l *Listen) Return() *Argument { return nil }
func (l *Listen) DecodeArguments(data []*byte, arglen int) error {
	l.Sock = types.InputFD(types.MakeC32(unsafe.Pointer(data[0])))
	l.Backlog = int(types.MakeC32(unsafe.Pointer(data[1])))

	return nil
}

func (l *Listen) Arguments() Arguments {
	return Arguments{
		{"sockfd", "int", l.Sock},
		{"backlog", "int", l.Backlog},
	}
}
