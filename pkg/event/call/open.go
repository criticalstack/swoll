package call

import (
	"unsafe"

	"github.com/criticalstack/swoll/pkg/types"
)

type Open struct {
	Filename string          `json:"filename"`
	Flags    types.FileFlags `json:"flags"`
	Mode     int             `json:"mode"`
	Ret      types.OutputFD  `json:"ret"`
}

func (o *Open) CallName() string  { return "open" }
func (o *Open) Return() *Argument { return &Argument{"out_fd", "int", o.Ret} }

func (o *Open) DecodeArguments(data []*byte, arglen int) error {
	o.Filename = types.MakeCString(unsafe.Pointer(data[0]), arglen)
	o.Flags = types.FileFlags(types.MakeC32(unsafe.Pointer(data[1])))
	o.Mode = int(types.MakeC32(unsafe.Pointer(data[2])))

	return nil
}

func (o *Open) Arguments() Arguments {
	return Arguments{
		{"pathname", "const char *", o.Filename},
		{"flags", "int", o.Flags},
		{"mode", "int", o.Mode},
	}
}
