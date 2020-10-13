package call

import (
	"unsafe"

	"github.com/criticalstack/swoll/pkg/types"
)

type Rmdir struct {
	Pathname string `json:"pathname"`
}

func (r *Rmdir) CallName() string  { return "rmdir" }
func (r *Rmdir) Return() *Argument { return nil }
func (r *Rmdir) DecodeArguments(data []*byte, arglen int) error {
	r.Pathname = types.MakeCString(unsafe.Pointer(data[0]), arglen)
	return nil
}

func (r *Rmdir) Arguments() Arguments {
	return Arguments{
		{"pathname", "const char *", r.Pathname},
	}
}
