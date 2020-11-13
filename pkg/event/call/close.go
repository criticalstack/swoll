package call

import (
	"unsafe"

	"github.com/criticalstack/swoll/pkg/types"
)

type Close struct {
	FD types.InputFD
}

func (c *Close) CallName() string  { return "close" }
func (c *Close) Return() *Argument { return nil }
func (c *Close) DecodeArguments(data []*byte, arglen int) error {
	c.FD = types.InputFD(types.MakeC32(unsafe.Pointer(data[0])))
	return nil
}
func (c *Close) Arguments() Arguments {
	return Arguments{
		{"fd", "int", c.FD},
	}
}
