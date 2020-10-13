package call

import (
	"os"
	"unsafe"

	"github.com/criticalstack/swoll/pkg/types"
)

// Mkdir ...
type Mkdir struct {
	Pathname string      `json:"pathname"`
	Mode     os.FileMode `json:"mode"`
}

func (m *Mkdir) CallName() string  { return "mkdir" }
func (m *Mkdir) Return() *Argument { return nil }
func (m *Mkdir) DecodeArguments(data []*byte, arglen int) error {
	m.Pathname = types.MakeCString(unsafe.Pointer(data[0]), arglen)
	m.Mode = os.FileMode(types.MakeC32(unsafe.Pointer(data[1])))
	return nil
}

func (m *Mkdir) Arguments() Arguments {
	return Arguments{
		{"pathname", "const char *", m.Pathname},
		{"mode", "mode_t", m.Mode},
	}
}
