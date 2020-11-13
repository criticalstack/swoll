package call

import (
	"unsafe"

	"github.com/criticalstack/swoll/pkg/types"
)

type Connect struct {
	FD    types.InputFD `json:"fd"`
	Saddr *types.SockAddr
}

func (c *Connect) CallName() string  { return "connect" }
func (c *Connect) Return() *Argument { return nil }
func (c *Connect) DecodeArguments(data []*byte, arglen int) error {
	c.FD = types.InputFD(types.MakeC32(unsafe.Pointer(data[0])))
	c.Saddr = (*types.SockAddr)(unsafe.Pointer(data[1]))
	return nil
}

func (c *Connect) Arguments() Arguments {
	return Arguments{
		{"sockfd", "int", c.FD},
		{"addr", "struct sockaddr *", c.Saddr},
	}
}
