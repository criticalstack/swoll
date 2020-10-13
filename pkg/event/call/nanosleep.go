package call

import (
	"C"

	"github.com/criticalstack/swoll/pkg/types"
)
import "unsafe"

type Nanosleep struct {
	Req types.Timespec `json:"req"`
	Rem types.Timespec `json:"rem"`
}

func (n *Nanosleep) CallName() string  { return "nanosleep" }
func (n *Nanosleep) Return() *Argument { return nil }
func (n *Nanosleep) DecodeArguments(data []*byte, arglen int) error {
	n.Req = *(*types.Timespec)(unsafe.Pointer(&data[0]))
	n.Rem = *(*types.Timespec)(unsafe.Pointer(&data[1]))
	return nil
}
func (n *Nanosleep) Arguments() Arguments {
	return Arguments{
		{"req", "void *", n.Req},
		{"rem", "void *", n.Rem},
	}
}
