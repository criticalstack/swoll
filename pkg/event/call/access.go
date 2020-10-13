package call

import (
	"unsafe"

	"github.com/criticalstack/swoll/pkg/types"
)

type Access struct {
	Pathname string           `json:"pathname"`
	Mode     types.XmodeFlags `json:"mode"`
}

func (a *Access) CallName() string  { return "access" }
func (a *Access) Return() *Argument { return nil }
func (a *Access) DecodeArguments(data []*byte, arglen int) error {
	a.Pathname = types.MakeCString(unsafe.Pointer(data[0]), arglen)
	a.Mode = types.XmodeFlags(types.MakeC32(unsafe.Pointer(data[1])))
	return nil
}

func (a *Access) Arguments() Arguments {
	return Arguments{
		{"pathname", "const char *", a.Pathname},
		{"mode", "int", a.Mode},
	}
}
