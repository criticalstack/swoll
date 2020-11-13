package call

import (
	"unsafe"

	"github.com/criticalstack/swoll/pkg/types"
)

type Recvfrom struct {
	FD    types.InputFD   `json:"fd"`
	Ubuf  types.Buffer    `json:"ubuf"`
	Size  int             `json:"size"`
	OSize int             `json:"o_size"`
	Flags types.MsgFlags  `json:"flags"`
	Saddr *types.SockAddr `json:"saddr"`
}

func (r *Recvfrom) CallName() string  { return "recvfrom" }
func (r *Recvfrom) Return() *Argument { return nil }
func (r *Recvfrom) DecodeArguments(data []*byte, arglen int) error {
	r.FD = types.InputFD(types.MakeC32(unsafe.Pointer(data[0])))
	// XXX[lz]: technically, the length of this buffer will be the RETURN VALUE
	// of this function, but for now, we just copy the whole buffer from the
	// kernel, and let the caller deal with the truncation.
	r.Ubuf = types.Buffer(types.MakeCBytes(unsafe.Pointer(data[1]), arglen))
	r.Flags = types.MsgFlags(types.MakeCU32(unsafe.Pointer(data[3])))
	r.Saddr = (*types.SockAddr)(unsafe.Pointer(data[4]))

	return nil
}

func (r *Recvfrom) Arguments() Arguments {
	return Arguments{
		{"sockfd", "int", r.FD},
		{"buf", "void *", r.Ubuf},
		{"len", "size_t", r.Size},
		{"flags", "int", r.Flags},
		{"src_addr", "struct sockaddr *", r.Saddr},
	}
}
