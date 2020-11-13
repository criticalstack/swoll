package call

import (
	"unsafe"

	"github.com/criticalstack/swoll/pkg/types"
)

type Exit struct {
	Code int `json:"code"`
}

func (e *Exit) CallName() string  { return "exit" }
func (e *Exit) Return() *Argument { return nil }
func (e *Exit) DecodeArguments(data []*byte, arglen int) error {
	e.Code = int(types.MakeC32(unsafe.Pointer(data[0])))
	return nil
}

func (e *Exit) Arguments() Arguments {
	return Arguments{
		{"status", "int", e.Code},
	}
}
