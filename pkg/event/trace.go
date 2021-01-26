package event

import (
	"encoding/json"
	"fmt"
	"syscall"

	"github.com/criticalstack/swoll/pkg/event/call"
	"github.com/criticalstack/swoll/pkg/syscalls"
	"github.com/criticalstack/swoll/pkg/types"
)

// TraceEvent is a more concrete version of the `RawEvent` structure, it
// includes data that needs to be "filled in" like the container information (as
// the kernel has no real idea what a container is)
type TraceEvent struct {
	Syscall      *syscalls.Syscall `json:"syscall"`
	Pid          int               `json:"pid"`
	Tid          int               `json:"tid"`
	CPid         int               `json:"container_pid"`
	UID          int               `json:"uid"`
	Gid          int               `json:"gid"`
	Comm         string            `json:"comm"`
	Sid          int               `json:"session"`
	Container    *types.Container  `json:"container"`
	Error        types.Errno       `json:"error"`
	Return       int               `json:"return"`
	PidNamespace int               `json:"pid_ns"`
	UtsNamespace int               `json:"uts_ns"`
	MntNamespace int               `json:"mount_ns"`
	Start        int64             `json:"start"`
	Finish       int64             `json:"finish"`
	Argv         call.Function     `json:"args"`
	// when the topology context is not nil, it is used
	// to resove container information.
	//topo            *topology.Topology
	lookupContainer ContainerLookupCb
	// Right now the only use for this is to copy the raw arguments
	// into the JSON version of this structure.
	raw *RawEvent
}

type ContainerLookupCb func(namespace int) (*types.Container, error)

func NewTraceEvent() *TraceEvent {
	return new(TraceEvent)
}

// ColorString is just a helper to display a stupid terminal-colored
// representation of a single event.
func (ev *TraceEvent) ColorString() string {
	return fmt.Sprintf("\033[1m%s:\033[0m [\033[4m%s\033[0m] %s(%s) err=%s ses=%v\n",
		ev.Container.FQDN(),
		ev.Comm,
		ev.Syscall.Name,
		ev.Argv,
		ev.Error.ColorString(),
		ev.Sid)
}

func (ev *TraceEvent) UnmarshalJSON(data []byte) error {
	type Alias TraceEvent
	n := &struct {
		*Alias
		Prgv json.RawMessage `json:"args"`
	}{
		Alias: (*Alias)(ev),
	}
	if err := json.Unmarshal(data, n); err != nil {
		return err
	}

	var args call.Function

	switch ev.Syscall.Nr {
	case syscall.SYS_ACCEPT:
		args = new(call.Accept)
	case syscall.SYS_ACCEPT4:
		args = new(call.Accept4)
	case syscall.SYS_ALARM:
		args = new(call.Alarm)
	case syscall.SYS_ACCT:
		args = new(call.Acct)
	case syscall.SYS_BRK:
		args = new(call.Brk)
	case syscall.SYS_CONNECT:
		args = new(call.Connect)
	case syscall.SYS_CLONE:
		args = new(call.Clone)
	case syscall.SYS_CLOSE:
		args = new(call.Close)
	case syscall.SYS_CREAT:
		args = new(call.Creat)
	case syscall.SYS_EXIT:
		args = new(call.Exit)
	case syscall.SYS_FACCESSAT:
		args = new(call.Faccessat)
	case syscall.SYS_FSTAT:
		args = new(call.Fstat)
	case syscall.SYS_FTRUNCATE:
		args = new(call.Ftruncate)
	case syscall.SYS_FUTEX:
		args = new(call.Futex)
	case syscall.SYS_GETCWD:
		args = new(call.Getcwd)
	case syscall.SYS_GETPEERNAME:
		args = new(call.Getpeername)
	case syscall.SYS_GETSOCKNAME:
		args = new(call.Getsockname)
	case syscall.SYS_GETSOCKOPT:
		args = new(call.Getsockopt)
	case syscall.SYS_INIT_MODULE:
		args = new(call.InitModule)
	case syscall.SYS_INOTIFY_ADD_WATCH:
		args = new(call.INotifyAddWatch)
	case syscall.SYS_KILL:
		args = new(call.Kill)
	case syscall.SYS_LINK:
		args = new(call.Link)
	case syscall.SYS_LISTEN:
		args = new(call.Listen)
	case syscall.SYS_MINCORE:
		args = new(call.Mincore)
	case syscall.SYS_MKDIR:
		args = new(call.Mkdir)
	case syscall.SYS_MOUNT:
		args = new(call.Mount)
	case syscall.SYS_MPROTECT:
		args = new(call.Mprotect)
	case syscall.SYS_NANOSLEEP:
		args = new(call.Nanosleep)
	case syscall.SYS_PIVOT_ROOT:
		args = new(call.PivotRoot)
	case syscall.SYS_PRLIMIT64:
		args = new(call.Prlimit64)
	case syscall.SYS_PTRACE:
		args = new(call.Ptrace)
	case syscall.SYS_READ:
		args = new(call.Read)
	case syscall.SYS_READLINK:
		args = new(call.Readlink)
	case syscall.SYS_READLINKAT:
		args = new(call.Readlinkat)
	case syscall.SYS_RECVFROM:
		args = new(call.Recvfrom)
	case syscall.SYS_RENAME:
		args = new(call.Rename)
	case syscall.SYS_RMDIR:
		args = new(call.Rmdir)
	case call.SYS_SECCOMP:
		args = new(call.Seccomp)
	case syscall.SYS_SENDTO:
		args = new(call.Sendto)
	case call.SYS_SETNS:
		args = new(call.Setns)
	case syscall.SYS_SETSOCKOPT:
		args = new(call.Setsockopt)
	case syscall.SYS_BIND:
		args = new(call.Bind)
	case syscall.SYS_EXECVE:
		args = new(call.Execve)
	case syscall.SYS_OPEN:
		args = new(call.Open)
	case syscall.SYS_OPENAT:
		args = new(call.Openat)
	case syscall.SYS_CHDIR:
		args = new(call.Chdir)
	case syscall.SYS_CHROOT:
		args = new(call.Chroot)
	case syscall.SYS_ACCESS:
		args = new(call.Access)
	case syscall.SYS_WRITE:
		args = new(call.Write)
	case syscall.SYS_UNLINK:
		args = new(call.Unlink)
	case syscall.SYS_UMOUNT2:
		args = new(call.Umount2)
	case syscall.SYS_TIMERFD_SETTIME:
		args = new(call.TimerFDSettime)
	case syscall.SYS_TIMERFD_CREATE:
		args = new(call.TimerFDCreate)
	case syscall.SYS_SYSLOG:
		args = new(call.Syslog)
	case syscall.SYS_SYMLINK:
		args = new(call.Symlink)
	case syscall.SYS_STATFS:
		args = new(call.Statfs)
	case syscall.SYS_STAT:
		args = new(call.Stat)
	case syscall.SYS_SOCKET:
		args = new(call.Socket)
	case syscall.SYS_SETUID:
		args = new(call.Setuid)

	}

	if err := json.Unmarshal(n.Prgv, args); err != nil {
		return err
	}

	ev.Argv = args
	return nil
}

/*
// WithTopology sets the internal topology context to `topo` for "resolving"
// kernel-namespaces to containers.
func (ev *TraceEvent) WithTopology(topo *topology.Topology) *TraceEvent {
	ev.topo = topo
	return ev
}
*/

// WithContainerLookup sets the callback to execute to resolve kernel namespaces
// to the container it is associated with.
func (ev *TraceEvent) WithContainerLookup(cb ContainerLookupCb) *TraceEvent {
	ev.lookupContainer = cb
	return ev
}

// Ingest reads an abstract input and outputs it as a fully-parsed TraceEvent.
// If a topology context has been set, it will also attempt to resolve the
// kernel-namespace to a pod/container.
func (ev *TraceEvent) Ingest(data interface{}) (*TraceEvent, error) {
	var err error
	rawEvent := new(RawEvent)

	switch data := data.(type) {
	case KernelEvent:
		ev.raw, err = rawEvent.Ingest(data)
		if err != nil {
			return nil, err
		}
	case []byte:
		ev.raw, err = rawEvent.Ingest(data)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("invalid input %T", data)
	}

	var container *types.Container

	if ev.lookupContainer != nil {
		container, _ = ev.lookupContainer(rawEvent.PidNamespace())
	}

	callData, err := call.DecodeSyscall(int(rawEvent.Syscall), rawEvent.Args(), rawEvent.ArgLen())
	if err != nil {
		fmt.Println(err)
		callData = data.(call.Function)
	}

	ev.PidNamespace = int(rawEvent.PidNS)
	ev.UtsNamespace = int(rawEvent.UtsNS)
	ev.MntNamespace = int(rawEvent.MntNS)
	ev.Container = container
	ev.Syscall = syscalls.Lookup(int(rawEvent.Syscall))
	ev.Return = int(rawEvent.Ret)
	ev.Finish = int64(rawEvent.Finish)
	ev.Error = types.Errno(rawEvent.Errno)
	ev.Start = int64(rawEvent.Start)
	ev.CPid = int(rawEvent.NsPid)
	ev.Comm = rawEvent.Commstr()
	ev.Argv = callData
	ev.Pid = int(rawEvent.Pid)
	ev.Tid = int(rawEvent.Tid)
	ev.UID = int(rawEvent.UID)
	ev.Gid = int(rawEvent.Gid)
	ev.Sid = int(rawEvent.Session)

	return ev, nil

}
