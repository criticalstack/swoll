package call

import (
	"unsafe"

	"github.com/criticalstack/swoll/pkg/types"
)

type Setuid struct {
	UID int `json:"uid"`
}

func (s *Setuid) CallName() string  { return "setuid" }
func (s *Setuid) Return() *Argument { return nil }
func (s *Setuid) DecodeArguments(data []*byte, arglen int) error {
	s.UID = int(types.MakeCU32(unsafe.Pointer(data[0])))
	return nil
}

func (s *Setuid) Arguments() Arguments {
	return Arguments{
		{"uid", "uid_t", s.UID},
	}
}
