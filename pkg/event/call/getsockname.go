package call

import (
	"unsafe"

	"github.com/criticalstack/swoll/pkg/types"
)

type Getsockname struct {
	FD    types.InputFD   `json:"fd"`
	Saddr *types.SockAddr `json:"saddr"`
}

func (g *Getsockname) CallName() string  { return "getsockname" }
func (g *Getsockname) Return() *Argument { return nil }
func (g *Getsockname) DecodeArguments(data []*byte, arglen int) error {
	g.FD = types.InputFD(types.MakeC32(unsafe.Pointer(data[0])))
	g.Saddr = (*types.SockAddr)(unsafe.Pointer(data[1]))
	return nil
}

func (g *Getsockname) Arguments() Arguments {
	return Arguments{
		{"sockfd", "int", g.FD},
		{"addr", "struct sockaddr *", g.Saddr},
	}
}
