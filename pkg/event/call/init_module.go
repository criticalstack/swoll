package call

import (
	"unsafe"

	"github.com/criticalstack/swoll/pkg/types"
)

type InitModule struct {
	Name   string `json:"name"`
	Len    int    `json:"len"`
	Params string `json:"params"`
}

func (i *InitModule) CallName() string  { return "init_module" }
func (i *InitModule) Return() *Argument { return nil }
func (i *InitModule) DecodeArguments(data []*byte, arglen int) error {
	i.Name = types.MakeCString(unsafe.Pointer(data[0]), arglen)
	i.Len = int(types.MakeCU64(unsafe.Pointer(data[1])))
	i.Params = types.MakeCString(unsafe.Pointer(data[2]), arglen)
	return nil
}

func (i *InitModule) Arguments() Arguments {
	return Arguments{
		{"module_image", "void *", i.Name},
		{"len", "unsigned long", i.Len},
		{"param_values", "const char *", i.Params},
	}
}
