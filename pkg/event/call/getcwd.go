package call

import (
	"unsafe"

	"github.com/criticalstack/swoll/pkg/types"
)

type Getcwd struct {
	Buf  string `json:"buf"`
	Size int    `json:"size"`
}

func (g *Getcwd) CallName() string  { return "getcwd" }
func (g *Getcwd) Return() *Argument { return nil }
func (g *Getcwd) DecodeArguments(data []*byte, arglen int) error {
	g.Buf = types.MakeCString(unsafe.Pointer(data[0]), arglen)
	g.Size = int(types.MakeCU64(unsafe.Pointer(data[1])))
	return nil
}

func (g *Getcwd) Arguments() Arguments {
	return Arguments{
		{"buf", "char *", g.Buf},
		{"size", "size_t", g.Size},
	}
}
