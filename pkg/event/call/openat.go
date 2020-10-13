package call

import (
	"unsafe"

	"github.com/criticalstack/swoll/pkg/types"
)

type Openat struct {
	DirFD    types.DirFD     `json:"dir_fd"`
	Pathname string          `json:"pathname"`
	Flags    types.FileFlags `json:"flags"`
}

func (o *Openat) CallName() string  { return "openat" }
func (o *Openat) Return() *Argument { return nil }

func (o *Openat) DecodeArguments(data []*byte, arglen int) error {
	o.DirFD = types.DirFD(types.MakeC32(unsafe.Pointer(data[0])))
	o.Pathname = types.MakeCString(unsafe.Pointer(data[1]), arglen)
	o.Flags = types.FileFlags(types.MakeC32(unsafe.Pointer(data[2])))
	return nil
}

func (o *Openat) Arguments() Arguments {
	return Arguments{
		{"dirfd", "int", o.DirFD},
		{"pathname", "const char *", o.Pathname},
		{"flags", "int", o.Flags},
	}
}
