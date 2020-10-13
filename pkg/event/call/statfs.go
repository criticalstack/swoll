package call

import (
	"syscall"
	"unsafe"

	"github.com/criticalstack/swoll/pkg/types"
)

type Statfs struct {
	Path    string         `json:"path"`
	StatBuf syscall.Stat_t `json:"stat_buf"`
}

func (s *Statfs) CallName() string  { return "statfs" }
func (s *Statfs) Return() *Argument { return nil }
func (s *Statfs) DecodeArguments(data []*byte, arglen int) error {
	s.Path = types.MakeCString(unsafe.Pointer(data[0]), arglen)
	s.StatBuf = *(*syscall.Stat_t)(unsafe.Pointer(data[1]))
	return nil
}

func (s *Statfs) Arguments() Arguments {
	return Arguments{
		{"path", "const char *", s.Path},
		{"buf", "struct statfs *", s.StatBuf},
	}
}
