package call

import (
	"os"
	"unsafe"

	"github.com/criticalstack/swoll/pkg/types"
)

type Creat struct {
	Pathname string      `json:"pathname"`
	Mode     os.FileMode `json:"mode"`
}

func (c *Creat) CallName() string  { return "creat" }
func (c *Creat) Return() *Argument { return nil }
func (c *Creat) DecodeArguments(data []*byte, arglen int) error {
	c.Pathname = types.MakeCString(unsafe.Pointer(data[0]), arglen)
	c.Mode = os.FileMode(types.MakeC32(unsafe.Pointer(data[1])))
	return nil
}

func (c *Creat) Arguments() Arguments {
	return Arguments{
		{"pathname", "const char *", c.Pathname},
		{"mode", "mode_t", c.Mode},
	}
}
