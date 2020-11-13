package call

import (
	"unsafe"

	"github.com/criticalstack/swoll/pkg/types"
)

type Symlink struct {
	Target   string `json:"target"`
	Linkpath string `json:"linkpath"`
}

func (s *Symlink) CallName() string  { return "symlink" }
func (s *Symlink) Return() *Argument { return nil }
func (s *Symlink) DecodeArguments(data []*byte, arglen int) error {
	s.Target = types.MakeCString(unsafe.Pointer(data[0]), arglen)
	s.Linkpath = types.MakeCString(unsafe.Pointer(data[1]), arglen)
	return nil
}

func (s *Symlink) Arguments() Arguments {
	return Arguments{
		{"target", "const char *", s.Target},
		{"linkpath", "const char *", s.Linkpath},
	}
}
