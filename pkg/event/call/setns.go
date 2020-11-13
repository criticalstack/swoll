package call

import (
	"unsafe"

	"github.com/criticalstack/swoll/pkg/types"
)

type Setns struct {
	FD     types.InputFD    `json:"fd"`
	NSType types.CloneFlags `json:"ns_type"`
}

const (
	CLONE_NEWCGROUP = 0x02000000
	CLONE_NEWUTS    = 0x04000000
	CLONE_NEWIPC    = 0x08000000
	CLONE_NEWUSER   = 0x10000000
	CLONE_NEWPID    = 0x20000000
	CLONE_NEWNET    = 0x40000000
	CLONE_NEWNS     = 0x00020000
)

func (s *Setns) CallName() string  { return "setns" }
func (s *Setns) Return() *Argument { return nil }
func (s *Setns) DecodeArguments(data []*byte, arglen int) error {
	s.FD = types.InputFD(types.MakeC32(unsafe.Pointer(data[0])))
	s.NSType = types.CloneFlags(types.MakeC32(unsafe.Pointer(data[1])))

	return nil
}

func (s *Setns) Arguments() Arguments {
	return Arguments{
		{"fd", "int", s.FD},
		{"nstype", "int", s.NSType},
	}
}
