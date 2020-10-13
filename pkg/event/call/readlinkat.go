package call

import (
	"unsafe"

	"github.com/criticalstack/swoll/pkg/types"
)

type Readlinkat struct {
	DirFD    types.DirFD  `json:"dir_fd"`
	Pathname string       `json:"pathname"`
	Buf      types.Buffer `json:"buf"`
	Bufsize  int          `json:"size"`
}

func (r *Readlinkat) CallName() string  { return "readlinkat" }
func (r *Readlinkat) Return() *Argument { return nil }
func (r *Readlinkat) DecodeArguments(data []*byte, arglen int) error {
	r.DirFD = types.DirFD(types.MakeC32(unsafe.Pointer(data[0])))
	r.Pathname = types.MakeCString(unsafe.Pointer(data[1]), arglen)
	r.Bufsize = int(types.MakeC64(unsafe.Pointer(data[3])))

	var bsz int

	if r.Bufsize < arglen {
		bsz = r.Bufsize
	} else {
		bsz = arglen
	}

	r.Buf = types.MakeCBytes(unsafe.Pointer(data[2]), bsz)

	return nil
}

func (r *Readlinkat) Arguments() Arguments {
	return Arguments{
		{"dirfd", "int", r.DirFD},
		{"pathname", "const char *", r.Pathname},
		{"buf", "char *", r.Buf},
		{"bufsiz", "size_t", r.Bufsize},
	}
}
