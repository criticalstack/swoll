package call

import (
	"unsafe"

	"github.com/criticalstack/swoll/pkg/types"
)

type Chdir struct {
	Filename string `json:"filename"`
}

func (c *Chdir) CallName() string  { return "chdir" }
func (c *Chdir) Return() *Argument { return nil }
func (c *Chdir) DecodeArguments(data []*byte, arglen int) error {
	c.Filename = types.MakeCString(unsafe.Pointer(data[0]), arglen)
	return nil
}

func (c *Chdir) Arguments() Arguments {
	return Arguments{
		{"path", "const char *", c.Filename},
	}
}
