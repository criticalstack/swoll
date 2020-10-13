package call

import (
	"unsafe"

	"github.com/criticalstack/swoll/pkg/types"
)

type Bind struct {
	FD    types.InputFD
	Ret   types.OutputFD
	Saddr *types.SockAddr
}

func (b *Bind) CallName() string  { return "bind" }
func (b *Bind) Return() *Argument { return &Argument{"out_fd", "int", b.Ret} }

func (b *Bind) DecodeArguments(data []*byte, arglen int) error {
	b.FD = types.InputFD(types.MakeC32(unsafe.Pointer(data[0])))
	b.Saddr = (*types.SockAddr)(unsafe.Pointer(data[1]))

	return nil
}

func (b *Bind) Arguments() Arguments {
	return Arguments{
		{"sockfd", "int", b.FD},
		{"addr", "struck sockaddr *", b.Saddr},
	}
}
