package call

import (
	"os"
	"unsafe"

	"github.com/criticalstack/swoll/pkg/types"
)

type Faccessat struct {
	FD       types.DirFD `json:"fd"`
	Pathname string      `json:"pathname"`
	Mode     os.FileMode `json:"mode"`
	Flags    int         `json:"flags"`
}

func (f *Faccessat) CallName() string  { return "faccessat" }
func (f *Faccessat) Return() *Argument { return nil }
func (f *Faccessat) DecodeArguments(data []*byte, arglen int) error {
	f.FD = types.DirFD(types.MakeC32(unsafe.Pointer(data[0])))
	f.Pathname = types.MakeCString(unsafe.Pointer(data[1]), arglen)
	f.Mode = os.FileMode(types.MakeC32(unsafe.Pointer(data[2])))
	f.Flags = int(types.MakeC32(unsafe.Pointer(data[3])))
	return nil
}

func (f *Faccessat) Arguments() Arguments {
	return Arguments{
		{"dirfd", "int", f.FD},
		{"pathname", "const char *", f.Pathname},
		{"mode", "int", f.Mode},
		{"flags", "int", f.Flags},
	}
}
