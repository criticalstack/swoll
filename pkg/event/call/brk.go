package call

import (
	"unsafe"

	"github.com/criticalstack/swoll/pkg/types"
)

type Brk struct {
	Addr uint64 `json:"addr"`
}

func (b *Brk) CallName() string  { return "brk" }
func (b *Brk) Return() *Argument { return nil }
func (b *Brk) DecodeArguments(data []*byte, arglen int) error {
	b.Addr = types.MakeCU64(unsafe.Pointer(data[0]))
	return nil
}

func (b *Brk) Arguments() Arguments {
	return Arguments{
		{"addr", "void *", b.Addr},
	}
}
