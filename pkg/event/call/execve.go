package call

import (
	"fmt"
	"unsafe"

	"github.com/criticalstack/swoll/pkg/types"
)

type Execve struct {
	Filename string    `json:"filename"`
	Argv     [4]string `json:"argv"`
}

func (e *Execve) CallName() string  { return "execve" }
func (e *Execve) Return() *Argument { return nil }
func (e *Execve) DecodeArguments(data []*byte, arglen int) error {
	e.Filename = types.MakeCString(unsafe.Pointer(data[0]), arglen)
	e.Argv[0] = types.MakeCString(unsafe.Pointer(data[1]), arglen)
	e.Argv[1] = types.MakeCString(unsafe.Pointer(data[2]), arglen)
	e.Argv[2] = types.MakeCString(unsafe.Pointer(data[3]), arglen)
	return nil
}

func (e *Execve) Arguments() Arguments {
	return Arguments{
		{"filename", "const char *", e.Filename},
		{"argv[]", "char * const", fmt.Sprintf("%s %s %s %s", e.Argv[0], e.Argv[1], e.Argv[2], e.Argv[3])},
	}
}
