package call

import (
	"unsafe"

	"github.com/criticalstack/swoll/pkg/types"
)

type Seccomp struct {
	Op    int    `json:"op"`
	Flags int    `json:"flags"`
	Args  string `json:"args"`
}

func (s *Seccomp) CallName() string  { return "seccomp" }
func (s *Seccomp) Return() *Argument { return nil }
func (s *Seccomp) DecodeArguments(data []*byte, arglen int) error {
	s.Op = int(types.MakeCU32(unsafe.Pointer(data[0])))
	s.Flags = int(types.MakeCU32(unsafe.Pointer(data[1])))
	s.Args = types.MakeCString(unsafe.Pointer(data[2]), arglen)
	return nil
}

func (s *Seccomp) Arguments() Arguments {
	return Arguments{
		{"operation", "unsigned int", s.Op},
		{"flags", "unsigned int", s.Flags},
		{"args", "void *", s.Args},
	}
}
