package call

import (
	"unsafe"

	"github.com/criticalstack/swoll/pkg/types"
)

type Readlink struct {
	Pathname string       `json:"pathname"`
	Buf      types.Buffer `json:"buf"`
	Bufsize  int          `json:"size"`
}

func (r *Readlink) CallName() string  { return "readlink" }
func (r *Readlink) Return() *Argument { return nil }
func (r *Readlink) DecodeArguments(data []*byte, arglen int) error {
	r.Pathname = types.MakeCString(unsafe.Pointer(data[0]), arglen)
	r.Bufsize = int(types.MakeC64(unsafe.Pointer(data[2])))

	var bsz int

	if r.Bufsize < arglen {
		bsz = r.Bufsize
	} else {
		bsz = arglen
	}

	r.Buf = types.MakeCBytes(unsafe.Pointer(data[1]), bsz)

	return nil
}

func (r *Readlink) Arguments() Arguments {
	return Arguments{
		{"pathname", "const char *", r.Pathname},
		{"buf", "char *", r.Buf},
		{"bufsiz", "size_t", r.Bufsize},
	}
}
