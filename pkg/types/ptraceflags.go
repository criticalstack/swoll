package types

import (
	"strings"
	"syscall"
)

const (
	// PTRACE_SEIZE ...
	PTRACE_SEIZE = 0x4206
	// PTRACE_INTERRUPT ...
	PTRACE_INTERRUPT = 0x4207
	// PTRACE_LISTEN ...
	PTRACE_LISTEN = 0x4208
	// PTRACE_PEEKSIGINFO ...
	PTRACE_PEEKSIGINFO = 0x4209
	// PTRACE_SECCOMP_GET_FILTER ...
	PTRACE_SECCOMP_GET_FILTER = 0x420c
)

type PtraceFlags int

var ptraceOptFlags = map[int]string{
	//syscall.PTRACE_O_TRACESECCOMP:   "PTRACE_O_TRACESECCOMP",
	syscall.PTRACE_O_TRACESYSGOOD:   "PTRACE_O_TRACESYSGOOD",
	syscall.PTRACE_O_TRACEFORK:      "PTRACE_O_TRACEFORK",
	syscall.PTRACE_O_TRACEVFORK:     "PTRACE_O_TRACEVFORK",
	syscall.PTRACE_O_TRACECLONE:     "PTRACE_O_TRACECLONE",
	syscall.PTRACE_O_TRACEEXEC:      "PTRACE_O_TRACEEXEC",
	syscall.PTRACE_O_TRACEVFORKDONE: "PTRACE_O_TRACEVFORKDONE",
	syscall.PTRACE_O_TRACEEXIT:      "PTRACE_O_TRACEEXIT",
}

/*
var ptraceReqTypes = map[int]string{
	//syscall.PTRACE_PEEKDATA_AREA:      "PTRACE_PEEKDATA_AREA",
	//syscall.PTRACE_PEEKUSR_AREA:       "PTRACE_PEEKUSR_AREA",
	//syscall.PTRACE_POKEUSER:           "PTRACE_POKEUSER",
	//syscall.PTRACE_POKEDATA_AREA:      "PTRACE_POKEDATA_AREA",
	//syscall.PTRACE_GETSIGMASK:         "PTRACE_GETSIGMASK",
	//syscall.PTRACE_SETSIGMASK:         "PTRACE_SETSIGMASK",
	//syscall.PTRACE_SECCOMP_GET_FILTER: "PTRACE_SECCOMP_GET_FILTER",
	PTRACE_SECCOMP_GET_FILTER:        "PTRACE_SECCOMP_GET_FILTER",
	PTRACE_LISTEN:                    "PTRACE_LISTEN",
	PTRACE_PEEKSIGINFO:               "PTRACE_PEEKSIGINFO",
	PTRACE_INTERRUPT:                 "PTRACE_INTERRUPT",
	PTRACE_SEIZE:                     "PTRACE_SEIZE",
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
*/

func (flags PtraceFlags) Parse() []string {
	ret := []string{}
	fint := int(flags)
	for mode, fstr := range ptraceOptFlags {
		if fint&mode != 0 {
			ret = append(ret, fstr)
		}
	}

	return ret
}

func (flags PtraceFlags) String() string {
	return strings.Join(flags.Parse(), "|")
}
