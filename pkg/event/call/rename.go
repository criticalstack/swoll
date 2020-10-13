package call

import (
	"unsafe"

	"github.com/criticalstack/swoll/pkg/types"
)

type Rename struct {
	OldName string `json:"old_name"`
	NewName string `json:"new_name"`
}

func (r *Rename) CallName() string  { return "rename" }
func (r *Rename) Return() *Argument { return nil }
func (r *Rename) DecodeArguments(data []*byte, arglen int) error {
	r.OldName = types.MakeCString(unsafe.Pointer(data[0]), arglen)
	r.NewName = types.MakeCString(unsafe.Pointer(data[1]), arglen)
	return nil
}

func (r *Rename) Arguments() Arguments {
	return Arguments{
		{"oldpath", "const char *", r.OldName},
		{"newpath", "const char *", r.NewName},
	}
}
