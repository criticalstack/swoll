package call

import (
	"syscall"
	"unsafe"

	"github.com/criticalstack/swoll/pkg/types"
)

type Fstat struct {
	FD      types.InputFD   `json:"fd"`
	StatBuf *syscall.Stat_t `json:"stat_buf"`
}

func (f *Fstat) CallName() string  { return "fstat" }
func (f *Fstat) Return() *Argument { return nil }
func (f *Fstat) DecodeArguments(data []*byte, arglen int) error {
	f.FD = types.InputFD(types.MakeC32(unsafe.Pointer(data[0])))
	f.StatBuf = (*syscall.Stat_t)(unsafe.Pointer(data[1]))

	return nil
}

func (f *Fstat) Arguments() Arguments {
	return Arguments{
		{"fd", "int", f.FD},
		{"statbuf", "struct stat *", f.StatBuf},
	}
}
