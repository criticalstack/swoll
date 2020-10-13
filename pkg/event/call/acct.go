package call

import (
	"unsafe"

	"github.com/criticalstack/swoll/pkg/types"
)

type Acct struct {
	Pathname string `json:"pathname"`
}

func (a *Acct) CallName() string  { return "acct" }
func (a *Acct) Return() *Argument { return nil }
func (a *Acct) DecodeArguments(data []*byte, arglen int) error {
	a.Pathname = types.MakeCString(unsafe.Pointer(data[0]), arglen)
	return nil
}

func (a *Acct) Arguments() Arguments {
	return Arguments{
		{"pathname", "const char *", a.Pathname},
	}
}
