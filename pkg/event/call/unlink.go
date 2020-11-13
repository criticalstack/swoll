package call

import (
	"unsafe"

	"github.com/criticalstack/swoll/pkg/types"
)

type Unlink struct {
	Pathname string `json:"pathname"`
}

func (u *Unlink) CallName() string  { return "unlink" }
func (u *Unlink) Return() *Argument { return nil }
func (u *Unlink) DecodeArguments(data []*byte, arglen int) error {
	u.Pathname = types.MakeCString(unsafe.Pointer(data[0]), arglen)
	return nil
}

func (u *Unlink) Arguments() Arguments {
	return Arguments{
		{"pathname", "const char *", u.Pathname},
	}
}
