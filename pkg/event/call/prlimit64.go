package call

import (
	"encoding/json"
	"fmt"
	"strconv"
	"syscall"
	"unsafe"

	"github.com/criticalstack/swoll/pkg/types"
)

type Rlimit syscall.Rlimit
type PRresource int

type Prlimit64 struct {
	Pid      int        `json:"pid"`
	Resource PRresource `json:"resource"`
	New      Rlimit     `json:"new"`
	Old      Rlimit     `json:"old"`
}

func (p *Prlimit64) CallName() string  { return "prlimit64" }
func (p *Prlimit64) Return() *Argument { return nil }
func (p *Prlimit64) DecodeArguments(data []*byte, arglen int) error {
	p.Pid = int(types.MakeC32(unsafe.Pointer(data[0])))
	p.Resource = PRresource(types.MakeC32(unsafe.Pointer(data[1])))
	p.New = *(*Rlimit)(unsafe.Pointer(data[2]))
	p.Old = *(*Rlimit)(unsafe.Pointer(data[3]))

	return nil
}

func (p *Prlimit64) Arguments() Arguments {
	return Arguments{
		{"pid", "pid_t", p.Pid},
		{"resource", "int", p.Resource},
		{"new_limit", "const struct rlimit *", p.New},
		{"old_limit", "struct rlimit *", p.Old},
	}
}

const (
	RLIMIT_RSS        = 5
	RLIMIT_NPROC      = 6
	RLIMIT_MEMLOCK    = 8
	RLIMIT_LOCKS      = 10
	RLIMIT_SIGPENDING = 11
	RLIMIT_MSGQUEUE   = 12
	RLIMIT_NICE       = 13
	RLIMIT_RTPRIO     = 14
	RLIMIT_RTTIME     = 15
)

func (r PRresource) Parse() string {
	switch r {
	case syscall.RLIMIT_AS:
		return "RLIMIT_AS"
	case syscall.RLIMIT_CORE:
		return "RLIMIT_CORE"
	case syscall.RLIMIT_CPU:
		return "RLIMIT_CPU"
	case syscall.RLIMIT_DATA:
		return "RLIMIT_DATA"
	case syscall.RLIMIT_FSIZE:
		return "RLIMIT_FSIZE"
	case syscall.RLIMIT_NOFILE:
		return "RLIMIT_NOFILE"
	case syscall.RLIMIT_STACK:
		return "RLIMIT_STACK"
	case RLIMIT_RSS:
		return "RLIMIT_RSS"
	case RLIMIT_NPROC:
		return "RLIMIT_NPROC"
	case RLIMIT_MEMLOCK:
		return "RLIMIT_MEMLOCK"
	case RLIMIT_LOCKS:
		return "RLIMIT_LOCKS"
	case RLIMIT_SIGPENDING:
		return "RLIMIT_SIGPENDING"
	case RLIMIT_MSGQUEUE:
		return "RLIMIT_MSGQUEUE"
	case RLIMIT_NICE:
		return "RLIMIT_NICE"
	case RLIMIT_RTPRIO:
		return "RLIMIT_RTPRIO"
	case RLIMIT_RTTIME:
		return "RLIMIT_RTTIME"
	default:
		return fmt.Sprintf("%d", r)
	}
}

func (r PRresource) String() string {
	return r.Parse()
}

func (r PRresource) MarshalJSON() ([]byte, error) {
	return json.Marshal(r.Parse())
}

func (r *PRresource) UnmarshalJSON(data []byte) error {
	var a string

	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}

	switch a {
	case "RLIMIT_AS":
		*r = syscall.RLIMIT_AS
	case "RLIMIT_CORE":
		*r = syscall.RLIMIT_CORE
	case "RLIMIT_CPU":
		*r = PRresource(syscall.RLIMIT_CPU)
	case "RLIMIT_DATA":
		*r = syscall.RLIMIT_DATA
	case "RLIMIT_FSIZE":
		*r = syscall.RLIMIT_FSIZE
	case "RLIMIT_NOFILE":
		*r = syscall.RLIMIT_NOFILE
	case "RLIMIT_STACK":
		*r = syscall.RLIMIT_STACK
	case "RLIMIT_RSS":
		*r = RLIMIT_RSS
	case "RLIMIT_NPROC":
		*r = RLIMIT_NPROC
	case "RLIMIT_MEMLOCK":
		*r = RLIMIT_MEMLOCK
	case "RLIMIT_LOCKS":
		*r = RLIMIT_LOCKS
	case "RLIMIT_SIGPENDING":
		*r = RLIMIT_SIGPENDING
	case "RLIMIT_MSGQUEUE":
		*r = RLIMIT_MSGQUEUE
	case "RLIMIT_NICE":
		*r = RLIMIT_NICE
	case "RLIMIT_RTPRIO":
		*r = RLIMIT_RTPRIO
	case "RLIMIT_RTTIME":
		*r = RLIMIT_RTTIME
	default:
		if val, err := strconv.Atoi(a); err != nil {
			return err
		} else {
			*r = PRresource(val)
		}
	}

	return nil
}
