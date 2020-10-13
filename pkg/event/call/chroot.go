package call

import (
	"unsafe"

	"github.com/criticalstack/swoll/pkg/types"
)

type Chroot struct {
	Filename string `json:"filename"`
}

func (c *Chroot) CallName() string  { return "chroot" }
func (c *Chroot) Return() *Argument { return nil }
func (c *Chroot) DecodeArguments(data []*byte, arglen int) error {
	c.Filename = types.MakeCString(unsafe.Pointer(data[0]), arglen)
	return nil
}

func (c *Chroot) Arguments() Arguments {
	return Arguments{
		{"path", "const char *", c.Filename},
	}
}
