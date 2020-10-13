package call

import (
	"unsafe"

	"github.com/criticalstack/swoll/pkg/types"
)

type Mincore struct {
	Addr uintptr `json:"addr"`
	Len  int     `json:"len"`
	Vec  uintptr `json:"vec"`
}

func (m *Mincore) CallName() string  { return "mincore" }
func (m *Mincore) Return() *Argument { return nil }
func (m *Mincore) DecodeArguments(data []*byte, arglen int) error {
	m.Addr = uintptr(types.MakeCU64(unsafe.Pointer(data[0])))
	m.Len = int(types.MakeCU64(unsafe.Pointer(data[1])))
	m.Vec = uintptr(types.MakeCU64(unsafe.Pointer(data[2])))
	return nil
}

func (m *Mincore) Arguments() Arguments {
	return Arguments{
		{"addr", "void *", m.Addr},
		{"len", "size_t", m.Len},
		{"vec", "unsigned char *", m.Vec},
	}
}
