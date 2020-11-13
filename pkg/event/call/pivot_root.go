package call

import (
	"unsafe"

	"github.com/criticalstack/swoll/pkg/types"
)

type PivotRoot struct {
	NewRoot string `json:"new_root"`
	OldRoot string `json:"old_root"`
}

func (p *PivotRoot) CallName() string  { return "pivot_root" }
func (p *PivotRoot) Return() *Argument { return nil }
func (p *PivotRoot) DecodeArguments(data []*byte, arglen int) error {
	p.NewRoot = types.MakeCString(unsafe.Pointer(data[0]), arglen)
	p.OldRoot = types.MakeCString(unsafe.Pointer(data[1]), arglen)

	return nil
}

func (p *PivotRoot) Arguments() Arguments {
	return Arguments{
		{"new_root", "const char *", p.NewRoot},
		{"put_old", "const char *", p.OldRoot},
	}
}
