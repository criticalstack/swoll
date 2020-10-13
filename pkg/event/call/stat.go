package call

import (
	"syscall"
	"unsafe"

	"github.com/criticalstack/swoll/pkg/types"
)

type Stat struct {
	Filename string         `json:"filename"`
	StatBuf  syscall.Stat_t `json:"stat_buf"`
}

func (s *Stat) CallName() string  { return "stat" }
func (s *Stat) Return() *Argument { return nil }
func (s *Stat) DecodeArguments(data []*byte, arglen int) error {
	s.Filename = types.MakeCString(unsafe.Pointer(data[0]), arglen)
	s.StatBuf = *(*syscall.Stat_t)(unsafe.Pointer(data[1]))

	return nil
}

func (s *Stat) Arguments() Arguments {
	return Arguments{
		{"pathname", "const char *", s.Filename},
		{"statbuf", "struct stat *", s.StatBuf},
	}
}
