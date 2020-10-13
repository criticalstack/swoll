package call

import (
	"unsafe"

	"github.com/criticalstack/swoll/pkg/types"
)

type Sendto struct {
	FD    types.InputFD   `json:"fd"`
	Ubuf  types.Buffer    `json:"ubuf"`
	Size  int             `json:"size"`
	Flags types.MsgFlags  `json:"flags"`
	Saddr *types.SockAddr `json:"saddr"`
}

func (s *Sendto) CallName() string  { return "sendto" }
func (s *Sendto) Return() *Argument { return nil }
func (s *Sendto) DecodeArguments(data []*byte, arglen int) error {
	s.FD = types.InputFD(types.MakeC32(unsafe.Pointer(data[0])))
	s.Ubuf = types.Buffer(types.MakeCBytes(unsafe.Pointer(data[1]), arglen))
	s.Size = int(types.MakeC64(unsafe.Pointer(data[2])))
	s.Flags = types.MsgFlags(types.MakeC32(unsafe.Pointer(data[3])))
	s.Saddr = (*types.SockAddr)(unsafe.Pointer(data[4]))

	return nil
}

func (s *Sendto) Arguments() Arguments {
	return Arguments{
		{"sockfd", "int", s.FD},
		{"buf", "const void *", s.Ubuf},
		{"len", "size_t", s.Size},
		{"flags", "int", s.Flags},
		{"dest_addr", "const struct sockaddr *", s.Saddr},
	}
}
