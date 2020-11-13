package call

import (
	"unsafe"

	"github.com/criticalstack/swoll/pkg/types"
)

type Getpeername struct {
	FD    types.InputFD   `json:"fd"`
	Saddr *types.SockAddr `json:"saddr"`
}

func (g *Getpeername) CallName() string  { return "getpeername" }
func (g *Getpeername) Return() *Argument { return nil }
func (g *Getpeername) DecodeArguments(data []*byte, arglen int) error {
	g.FD = types.InputFD(types.MakeC32(unsafe.Pointer(data[0])))
	g.Saddr = (*types.SockAddr)(unsafe.Pointer(data[1]))
	return nil
}

func (g *Getpeername) Arguments() Arguments {
	return Arguments{
		{"sockfd", "int", g.FD},
		{"addr", "struct sockaddr *", g.Saddr},
	}
}
