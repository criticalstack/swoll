package call

import (
	"unsafe"

	"github.com/criticalstack/swoll/pkg/types"
)

type Syslog struct {
	Type int    `json:"type"`
	Buf  string `json:"buf"`
	Len  int    `json:"len"`
}

func (s *Syslog) CallName() string  { return "syslog" }
func (s *Syslog) Return() *Argument { return nil }
func (s *Syslog) DecodeArguments(data []*byte, arglen int) error {
	s.Type = int(types.MakeC32(unsafe.Pointer(data[0])))
	s.Buf = types.MakeCString(unsafe.Pointer(data[1]), arglen)
	s.Len = int(types.MakeC32(unsafe.Pointer(data[2])))
	return nil
}

func (s *Syslog) Arguments() Arguments {
	return Arguments{
		{"type", "int", s.Type},
		{"bufp", "char *", s.Buf},
		{"len", "int", s.Len},
	}

}
