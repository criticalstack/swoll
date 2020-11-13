// +build ignore

package call

import (
	"C"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/criticalstack/swoll/pkg/types"
)

/*
	field:int size;	offset:16;	size:8;	signed:0;
*/
type EpollCreate struct {
	EpFD  types.InputFD
	Size  int
	Flags int
}

/*
	field:int epfd;	offset:16;	size:8;	signed:0;
	field:int op;	offset:24;	size:8;	signed:0;
	field:int fd;	offset:32;	size:8;	signed:0;
	field:struct epoll_event * event;	offset:40;	size:8;	signed:0;
*/
type EpollCtl struct {
	EpFD  types.InputFD
	Op    int
	FD    types.InputFD
	Event *syscall.EpollEvent
}

/*
	field:int epfd;	offset:16;	size:8;	signed:0;
	field:struct epoll_event * events;	offset:24;	size:8;	signed:0;
	field:int maxevents;	offset:32;	size:8;	signed:0;
	field:int timeout;	offset:40;	size:8;	signed:0;
*/
type EpollWait struct {
	EpFD      types.InputFD
	Events    []*syscall.EpollEvent
	MaxEvents int
	Timeout   int
}

/*
	field:int epfd;	offset:16;	size:8;	signed:0;
	field:struct epoll_event * events;	offset:24;	size:8;	signed:0;
	field:int maxevents;	offset:32;	size:8;	signed:0;
	field:int timeout;	offset:40;	size:8;	signed:0;
	field:const sigset_t * sigmask;	offset:48;	size:8;	signed:0;
	field:size_t sigsetsize;	offset:56;	size:8;	signed:0;
*/

type EpollPWait struct {
	EpFD       types.InputFD
	Events     []*syscall.EpollEvent
	MaxEvents  int
	Timeout    int
	Sigmask    *unix.Sigset_t
	Sigsetsize int
}

///EpollCreate
func (e *EpollCreate) CallName() string  { return "epoll_create" }
func (e *EpollCreate) Return() *Argument { return nil }
func (e *EpollCreate) DecodeArguments(data []*byte) error {
	e.EpFD = types.InputFD(*(*C.longlong)(unsafe.Pointer(data[0])))
	e.Size = int(*(*C.longlong)(unsafe.Pointer(data[1])))
	e.Flags = int(*(*C.longlong)(unsafe.Pointer(data[2])))
	return nil
}
func (e *EpollCreate) Arguments() Arguments {
	return Arguments{
		{"epfd", "int", e.EpFD},
		{"size", "int", e.Size},
		{"flags", "int", e.Flags},
	}
}

///EpollCtl
func (e *EpollCtl) CallName() string  { return "epoll_ctl" }
func (e *EpollCtl) Return() *Argument { return nil }
func (e *EpollCtl) DecodeArguments(data []*byte) error {
	e.EpFD = types.InputFD(*(*C.longlong)(unsafe.Pointer(data[0])))
	e.Op = int(*(*C.longlong)(unsafe.Pointer(data[1])))
	e.FD = types.InputFD(*(*C.longlong)(unsafe.Pointer(data[2])))
	e.Event = (*syscall.EpollEvent)((unsafe.Pointer)(unsafe.Pointer(data[3])))
	return nil
}
func (e *EpollCtl) Arguments() Arguments {
	return Arguments{
		{"epfd", "int", e.EpFD},
		{"op", "int", e.Op},
		{"fd", "int", e.FD},
		{"event", "struct epoll_event *", e.Event},
	}
}

////EpollWait
func (e *EpollWait) CallName() string  { return "epoll_wait" }
func (e *EpollWait) Return() *Argument { return nil }
func (e *EpollWait) DecodeArguments(data []*byte) error {
	e.EpFD = types.InputFD(*(*C.longlong)(unsafe.Pointer(data[0])))
	e.Events = *(*[]*syscall.EpollEvent)(unsafe.Pointer(uintptr(unsafe.Pointer(&data[1])) + unsafe.Sizeof(&data[1])))
	e.MaxEvents = int(*(*C.longlong)(unsafe.Pointer(data[2])))
	e.Timeout = int(*(*C.longlong)(unsafe.Pointer(data[3])))
	return nil
}
func (e *EpollWait) Arguments() Arguments {
	return Arguments{
		{"epfd", "int", e.EpFD},
		{"event", "int", e.Events},
		{"max_events", "int", e.MaxEvents},
		{"timeout", "int", e.Timeout},
	}
}

////EpoolPWait
func (e *EpollPWait) CallName() string  { return "epoll_pwait" }
func (e *EpollPWait) Return() *Argument { return nil }
func (e *EpollPWait) DecodeArguments(data []*byte) error {
	e.EpFD = types.InputFD(*(*C.longlong)(unsafe.Pointer(data[0])))
	e.Events = *(*[]*syscall.EpollEvent)(unsafe.Pointer(uintptr(unsafe.Pointer(&data[1])) + unsafe.Sizeof(&data[1])))
	e.MaxEvents = int(*(*C.longlong)(unsafe.Pointer(data[2])))
	e.Timeout = int(*(*C.longlong)(unsafe.Pointer(data[3])))
	e.Sigmask = (*unix.Sigset_t)(unsafe.Pointer(data[4]))
	e.Sigsetsize = int(*(*C.longlong)(unsafe.Pointer(data[5])))
	return nil
}
func (e *EpollPWait) Arguments() Arguments {
	return Arguments{
		{"epfd", "int", e.EpFD},
		{"event", "int", e.Events},
		{"max_events", "int", e.MaxEvents},
		{"timeout", "int", e.Timeout},
		{"signmask", "const sigset_t *", e.Sigmask},
		{"signsetsize", "int", e.Sigsetsize},
	}
}
