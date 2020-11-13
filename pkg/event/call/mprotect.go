package call

import (
	"strings"
	"syscall"
	"unsafe"

	"github.com/criticalstack/swoll/pkg/types"
)

type ProtFlags int
type Mprotect struct {
	Addr     uintptr      `json:"addr"`
	Len      int          `json:"len"`
	Prot     ProtFlags    `json:"prot"`
	AddrData types.Buffer `json:"addr_data"`
}

func (m *Mprotect) CallName() string  { return "mprotect" }
func (m *Mprotect) Return() *Argument { return nil }
func (m *Mprotect) DecodeArguments(data []*byte, arglen int) error {
	m.Addr = uintptr(types.MakeCU64(unsafe.Pointer(data[0])))
	m.Len = int(types.MakeCU64(unsafe.Pointer(data[1])))
	m.Prot = ProtFlags(types.MakeC32(unsafe.Pointer(data[2])))

	if arglen < m.Len {
		arglen = m.Len
	}

	// this is a special case from our probe which will dereference that memory
	// region at `Addr`
	m.AddrData = types.MakeCBytes(unsafe.Pointer(data[3]), arglen)
	return nil
}

func (m *Mprotect) Arguments() Arguments {
	return Arguments{
		{"addr", "void *", m.Addr},
		{"len", "size_t", m.Len},
		{"prot", "int", m.Prot},
	}
}

const PROT_SEM = 0x8

var protMasks = map[int]string{
	syscall.PROT_NONE:      "PROT_NONE",
	syscall.PROT_READ:      "PROT_READ",
	syscall.PROT_WRITE:     "PROT_WRITE",
	syscall.PROT_EXEC:      "PROT_EXEC",
	PROT_SEM:               "PROT_SEM",
	syscall.PROT_GROWSUP:   "PROT_GROWSUP",
	syscall.PROT_GROWSDOWN: "PROT_GROWSDOWN",
}

func (flags ProtFlags) Parse() []string {
	if flags == 0 {
		return []string{"PROT_NONE"}
	}

	ret := []string{}
	fint := int(flags)

	for flag, fstr := range protMasks {
		if fint&flag != 0 {
			ret = append(ret, fstr)
		}
	}

	return ret
}

func (flags ProtFlags) String() string {
	return strings.Join(flags.Parse(), "|")
}

/*
func (flags ProtFlags) MarshalJSON() ([]byte, error) {
	return json.Marshal(flags.Parse())
}
*/
