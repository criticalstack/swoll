package call

import (
	"fmt"
	"unsafe"

	"github.com/criticalstack/swoll/pkg/types"
)

type Clone struct {
	Flags       types.CloneFlags `json:"flags"`
	NewStack    uint64           `json:"new_stack"`
	ChildStack  uint64           `json:"child_stack"`
	ParentStack uint64           `json:"parent_stack"`
	Tls         uint64           `json:"tls"`
}

func (c *Clone) CallName() string  { return "clone" }
func (c *Clone) Return() *Argument { return nil }
func (c *Clone) DecodeArguments(data []*byte, arglen int) error {
	c.Flags = types.CloneFlags(types.MakeCU64(unsafe.Pointer(data[0])))
	c.NewStack = uint64(types.MakeCU64(unsafe.Pointer(data[1])))
	c.ChildStack = uint64(types.MakeCU64(unsafe.Pointer(data[2])))
	c.ParentStack = uint64(types.MakeCU64(unsafe.Pointer(data[3])))
	c.Tls = uint64(types.MakeCU64(unsafe.Pointer(data[4])))

	return nil
}

func (c *Clone) Arguments() Arguments {
	return Arguments{
		{"fn", "int (*)(void *)", fmt.Sprintf("0x%08x", c.NewStack)},
		{"child_stack", "void *", fmt.Sprintf("0x%08x", c.ChildStack)},
		{"flags", "int", c.Flags},
	}
}
