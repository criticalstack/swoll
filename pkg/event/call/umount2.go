package call

import (
	"unsafe"

	"github.com/criticalstack/swoll/pkg/types"
)

type Umount2 struct {
	Target string            `json:"target"`
	Flags  types.UmountFlags `json:"flags"`
}

func (u *Umount2) CallName() string  { return "umount" }
func (u *Umount2) Return() *Argument { return nil }
func (u *Umount2) DecodeArguments(data []*byte, arglen int) error {
	u.Target = types.MakeCString(unsafe.Pointer(data[0]), arglen)
	u.Flags = types.UmountFlags(types.MakeC32(unsafe.Pointer(data[1])))
	return nil
}

func (u *Umount2) Arguments() Arguments {
	return Arguments{
		{"target", "const char *", u.Target},
		{"flags", "int", u.Flags},
	}
}
