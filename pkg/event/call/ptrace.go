package call

import (
	"fmt"
	"syscall"
	"unsafe"

	"github.com/criticalstack/swoll/pkg/types"
)

type PtraceRequest int
type PtraceData uint64

type Ptrace struct {
	Request PtraceRequest `json:"request"`
	PID     int           `json:"pid"`
	Addr    uint64        `json:"addr"`
	Data    PtraceData    `json:"data"`
}

func (p *Ptrace) CallName() string  { return "ptrace" }
func (p *Ptrace) Return() *Argument { return nil }
func (p *Ptrace) DecodeArguments(data []*byte, arglen int) error {
	p.Request = PtraceRequest(types.MakeC32(unsafe.Pointer(data[0])))
	p.PID = int(types.MakeC32(unsafe.Pointer(data[1])))
	p.Addr = types.MakeCU64(unsafe.Pointer(data[2]))
	p.Data = PtraceData(types.MakeCU64(unsafe.Pointer(data[3])))

	return nil
}

func (p *Ptrace) Arguments() Arguments {
	return Arguments{
		{"request", "enum __ptrace_request", p.Request},
		{"pid", "pid_t", p.PID},
		{"addr", "void *", p.Addr},
		{"data", "void *", p.Data},
	}
}

const (
	PTRACE_SEIZE              = 0x4206
	PTRACE_INTERRUPT          = 0x4207
	PTRACE_LISTEN             = 0x4208
	PTRACE_PEEKSIGINFO        = 0x4209
	PTRACE_SECCOMP_GET_FILTER = 0x420c
	PTRACE_GET_SYSCALL_INFO   = 0x420e
)

var ptraceReqTypes = map[int]string{
	PTRACE_SECCOMP_GET_FILTER:        "PTRACE_SECCOMP_GET_FILTER",
	PTRACE_LISTEN:                    "PTRACE_LISTEN",
	PTRACE_PEEKSIGINFO:               "PTRACE_PEEKSIGINFO",
	PTRACE_INTERRUPT:                 "PTRACE_INTERRUPT",
	PTRACE_SEIZE:                     "PTRACE_SEIZE",
	PTRACE_GET_SYSCALL_INFO:          "PTRACE_GET_SYSCALL_INFO",
	syscall.PTRACE_PEEKDATA:          "PTRACE_PEEKDATA",
	syscall.PTRACE_PEEKUSR:           "PTRACE_PEEKUSER",
	syscall.PTRACE_TRACEME:           "PTRACE_TRACEME",
	syscall.PTRACE_PEEKTEXT:          "PTRACE_PEEKTEXT",
	syscall.PTRACE_POKETEXT:          "PTRACE_POKETEXT",
	syscall.PTRACE_GETREGS:           "PTRACE_GETREGS",
	syscall.PTRACE_GETFPREGS:         "PTRACE_GETFPREGS",
	syscall.PTRACE_GETREGSET:         "PTRACE_GETREGSET",
	syscall.PTRACE_SETREGS:           "PTRACE_SETREGS",
	syscall.PTRACE_SETFPREGS:         "PTRACE_SETFPREGS",
	syscall.PTRACE_SETREGSET:         "PTRACE_SETREGSET",
	syscall.PTRACE_GETSIGINFO:        "PTRACE_GETSIGINFO",
	syscall.PTRACE_SETSIGINFO:        "PTRACE_SETSIGINFO",
	syscall.PTRACE_SETOPTIONS:        "PTRACE_SETOPTIONS",
	syscall.PTRACE_GETEVENTMSG:       "PTRACE_GETEVENTMSG",
	syscall.PTRACE_CONT:              "PTRACE_CONT",
	syscall.PTRACE_SYSCALL:           "PTRACE_SYSCALL",
	syscall.PTRACE_SINGLESTEP:        "PTRACE_SINGLESTEP",
	syscall.PTRACE_SYSEMU:            "PTRACE_SYSEMU",
	syscall.PTRACE_SYSEMU_SINGLESTEP: "PTRACE_SYSEMU_SINGLESTEP",
	syscall.PTRACE_KILL:              "PTRACE_KILL",
	syscall.PTRACE_ATTACH:            "PTRACE_ATTACH",
	syscall.PTRACE_DETACH:            "PTRACE_DETACH",
	syscall.PTRACE_GET_THREAD_AREA:   "PTRACE_GET_THREAD_AREA",
	syscall.PTRACE_SET_THREAD_AREA:   "PTRACE_SET_THREAD_AREA",
}

func (p PtraceRequest) Parse() string {
	if v, ok := ptraceReqTypes[int(p)]; ok {
		return v
	}

	return fmt.Sprintf("%d", p)
}

func (p PtraceRequest) String() string {
	return p.Parse()
}
