package call

import (
	"unsafe"

	"github.com/criticalstack/swoll/pkg/types"
)

type Link struct {
	OldName string `json:"old_name"`
	NewName string `json:"new_name"`
}

func (l *Link) CallName() string  { return "link" }
func (l *Link) Return() *Argument { return nil }
func (l *Link) DecodeArguments(data []*byte, arglen int) error {
	l.OldName = types.MakeCString(unsafe.Pointer(data[0]), arglen)
	l.NewName = types.MakeCString(unsafe.Pointer(data[1]), arglen)
	return nil
}

func (l *Link) Arguments() Arguments {
	return Arguments{
		{"oldpath", "const char *", l.OldName},
		{"newpath", "const char *", l.NewName},
	}
}
