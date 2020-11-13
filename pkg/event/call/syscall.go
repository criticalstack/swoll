package call

import (
	"fmt"
	"syscall"
)

const (
	SYS_SECCOMP = 317
	SYS_SETNS   = 308
)

func DecodeSyscall(nr int, arguments []*byte, arglen int) (interface{}, error) {
	switch nr {
	case syscall.SYS_ACCEPT:
		ret := new(Accept)
		return ret, ret.DecodeArguments(arguments, arglen)
	case syscall.SYS_ACCEPT4:
		ret := new(Accept4)
		return ret, ret.DecodeArguments(arguments, arglen)
	case syscall.SYS_ALARM:
		ret := new(Alarm)
		return ret, ret.DecodeArguments(arguments, arglen)
	case syscall.SYS_ACCT:
		ret := new(Acct)
		return ret, ret.DecodeArguments(arguments, arglen)
	case syscall.SYS_BRK:
		ret := new(Brk)
		return ret, ret.DecodeArguments(arguments, arglen)
	case syscall.SYS_CONNECT:
		ret := new(Connect)
		return ret, ret.DecodeArguments(arguments, arglen)
	case syscall.SYS_CLONE:
		ret := new(Clone)
		return ret, ret.DecodeArguments(arguments, arglen)
	case syscall.SYS_CLOSE:
		ret := new(Close)
		return ret, ret.DecodeArguments(arguments, arglen)
	case syscall.SYS_CREAT:
		ret := new(Creat)
		return ret, ret.DecodeArguments(arguments, arglen)
	case syscall.SYS_EXIT:
		ret := new(Exit)
		return ret, ret.DecodeArguments(arguments, arglen)
	case syscall.SYS_FACCESSAT:
		ret := new(Faccessat)
		return ret, ret.DecodeArguments(arguments, arglen)
	case syscall.SYS_FSTAT:
		ret := new(Fstat)
		return ret, ret.DecodeArguments(arguments, arglen)
	case syscall.SYS_FTRUNCATE:
		ret := new(Ftruncate)
		return ret, ret.DecodeArguments(arguments, arglen)
	case syscall.SYS_FUTEX:
		ret := new(Futex)
		return ret, ret.DecodeArguments(arguments, arglen)
	case syscall.SYS_GETCWD:
		ret := new(Getcwd)
		return ret, ret.DecodeArguments(arguments, arglen)
	case syscall.SYS_GETPEERNAME:
		ret := new(Getpeername)
		return ret, ret.DecodeArguments(arguments, arglen)
	case syscall.SYS_GETSOCKNAME:
		ret := new(Getsockname)
		return ret, ret.DecodeArguments(arguments, arglen)
	case syscall.SYS_GETSOCKOPT:
		ret := new(Getsockopt)
		return ret, ret.DecodeArguments(arguments, arglen)
	case syscall.SYS_INIT_MODULE:
		ret := new(InitModule)
		return ret, ret.DecodeArguments(arguments, arglen)
	case syscall.SYS_INOTIFY_ADD_WATCH:
		ret := new(INotifyAddWatch)
		return ret, ret.DecodeArguments(arguments, arglen)
	case syscall.SYS_KILL:
		ret := new(Kill)
		return ret, ret.DecodeArguments(arguments, arglen)
	case syscall.SYS_LINK:
		ret := new(Link)
		return ret, ret.DecodeArguments(arguments, arglen)
	case syscall.SYS_LISTEN:
		ret := new(Listen)
		return ret, ret.DecodeArguments(arguments, arglen)
	case syscall.SYS_MINCORE:
		ret := new(Mincore)
		return ret, ret.DecodeArguments(arguments, arglen)
	case syscall.SYS_MKDIR:
		ret := new(Mkdir)
		return ret, ret.DecodeArguments(arguments, arglen)
	case syscall.SYS_MOUNT:
		ret := new(Mount)
		return ret, ret.DecodeArguments(arguments, arglen)
	case syscall.SYS_MPROTECT:
		ret := new(Mprotect)
		return ret, ret.DecodeArguments(arguments, arglen)
	case syscall.SYS_NANOSLEEP:
		ret := new(Nanosleep)
		return ret, ret.DecodeArguments(arguments, arglen)
	case syscall.SYS_PIVOT_ROOT:
		ret := new(PivotRoot)
		return ret, ret.DecodeArguments(arguments, arglen)
	case syscall.SYS_PRLIMIT64:
		ret := new(Prlimit64)
		return ret, ret.DecodeArguments(arguments, arglen)
	case syscall.SYS_PTRACE:
		ret := new(Ptrace)
		return ret, ret.DecodeArguments(arguments, arglen)
	case syscall.SYS_READ:
		ret := new(Read)
		return ret, ret.DecodeArguments(arguments, arglen)
	case syscall.SYS_READLINK:
		ret := new(Readlink)
		return ret, ret.DecodeArguments(arguments, arglen)
	case syscall.SYS_READLINKAT:
		ret := new(Readlinkat)
		return ret, ret.DecodeArguments(arguments, arglen)
	case syscall.SYS_RECVFROM:
		ret := new(Recvfrom)
		return ret, ret.DecodeArguments(arguments, arglen)
	case syscall.SYS_RENAME:
		ret := new(Rename)
		return ret, ret.DecodeArguments(arguments, arglen)
	case syscall.SYS_RMDIR:
		ret := new(Rmdir)
		return ret, ret.DecodeArguments(arguments, arglen)
	case SYS_SECCOMP:
		ret := new(Seccomp)
		return ret, ret.DecodeArguments(arguments, arglen)
	case syscall.SYS_SENDTO:
		ret := new(Sendto)
		return ret, ret.DecodeArguments(arguments, arglen)
	case SYS_SETNS:
		ret := new(Setns)
		return ret, ret.DecodeArguments(arguments, arglen)
	case syscall.SYS_SETSOCKOPT:
		ret := new(Setsockopt)
		return ret, ret.DecodeArguments(arguments, arglen)
	case syscall.SYS_BIND:
		ret := new(Bind)
		return ret, ret.DecodeArguments(arguments, arglen)
	case syscall.SYS_EXECVE:
		ret := new(Execve)
		return ret, ret.DecodeArguments(arguments, arglen)
	case syscall.SYS_OPEN:
		ret := new(Open)
		return ret, ret.DecodeArguments(arguments, arglen)
	case syscall.SYS_OPENAT:
		ret := new(Openat)
		return ret, ret.DecodeArguments(arguments, arglen)
	case syscall.SYS_CHDIR:
		ret := new(Chdir)
		return ret, ret.DecodeArguments(arguments, arglen)
	case syscall.SYS_CHROOT:
		ret := new(Chroot)
		return ret, ret.DecodeArguments(arguments, arglen)
	case syscall.SYS_ACCESS:
		ret := new(Access)
		return ret, ret.DecodeArguments(arguments, arglen)
	case syscall.SYS_WRITE:
		ret := new(Write)
		return ret, ret.DecodeArguments(arguments, arglen)
	case syscall.SYS_UNLINK:
		ret := new(Unlink)
		return ret, ret.DecodeArguments(arguments, arglen)
	case syscall.SYS_UMOUNT2:
		ret := new(Umount2)
		return ret, ret.DecodeArguments(arguments, arglen)
	case syscall.SYS_TIMERFD_SETTIME:
		ret := new(TimerFDSettime)
		return ret, ret.DecodeArguments(arguments, arglen)
	case syscall.SYS_TIMERFD_CREATE:
		ret := new(TimerFDCreate)
		return ret, ret.DecodeArguments(arguments, arglen)
	case syscall.SYS_SYSLOG:
		ret := new(Syslog)
		return ret, ret.DecodeArguments(arguments, arglen)
	case syscall.SYS_SYMLINK:
		ret := new(Symlink)
		return ret, ret.DecodeArguments(arguments, arglen)
	case syscall.SYS_STATFS:
		ret := new(Statfs)
		return ret, ret.DecodeArguments(arguments, arglen)
	case syscall.SYS_STAT:
		ret := new(Stat)
		return ret, ret.DecodeArguments(arguments, arglen)
	case syscall.SYS_SOCKET:
		ret := new(Socket)
		return ret, ret.DecodeArguments(arguments, arglen)
	case syscall.SYS_SETUID:
		ret := new(Setuid)
		return ret, ret.DecodeArguments(arguments, arglen)
	default:
		return nil, fmt.Errorf("unhandled syscall: %v", nr)
	}

}

/*
func DecodeSyscall(nr int, arguments []*byte, arglen int) (*FunctionHandle, error) {
	var ret *FunctionHandle
	switch nr {
	case syscall.SYS_ACCEPT:
		ret = &FunctionHandle{new(Accept)}
	case syscall.SYS_ACCEPT4:
		ret = &FunctionHandle{new(Accept4)}
	case syscall.SYS_ALARM:
		ret = &FunctionHandle{new(Alarm)}
	case syscall.SYS_ACCT:
		ret = &FunctionHandle{new(Acct)}
	case syscall.SYS_BRK:
		ret = &FunctionHandle{new(Brk)}
	//case syscall.SYS_IOCTL:
	// XXX[lz]: not ready
	//	ret = &FunctionHandle{new(Ioctl)}
	case syscall.SYS_CONNECT:
		ret = &FunctionHandle{new(Connect)}
	case syscall.SYS_CLONE:
		ret = &FunctionHandle{new(Clone)}
	case syscall.SYS_CLOSE:
		ret = &FunctionHandle{new(Close)}
	case syscall.SYS_CREAT:
		ret = &FunctionHandle{new(Creat)}
	case syscall.SYS_EXIT:
		ret = &FunctionHandle{new(Exit)}
	case syscall.SYS_FACCESSAT:
		ret = &FunctionHandle{new(Faccessat)}
	case syscall.SYS_FSTAT:
		ret = &FunctionHandle{new(Fstat)}
	case syscall.SYS_FTRUNCATE:
		ret = &FunctionHandle{new(Ftruncate)}
	case syscall.SYS_FUTEX:
		ret = &FunctionHandle{new(Futex)}
	case syscall.SYS_GETCWD:
		ret = &FunctionHandle{new(Getcwd)}
	case syscall.SYS_GETPEERNAME:
		ret = &FunctionHandle{new(Getpeername)}
	case syscall.SYS_GETSOCKNAME:
		ret = &FunctionHandle{new(Getsockname)}
	case syscall.SYS_GETSOCKOPT:
		ret = &FunctionHandle{new(Getsockopt)}
	case syscall.SYS_INIT_MODULE:
		ret = &FunctionHandle{new(InitModule)}
	case syscall.SYS_INOTIFY_ADD_WATCH:
		ret = &FunctionHandle{new(INotifyAddWatch)}
	case syscall.SYS_KILL:
		ret = &FunctionHandle{new(Kill)}
	case syscall.SYS_LINK:
		ret = &FunctionHandle{new(Link)}
	case syscall.SYS_LISTEN:
		ret = &FunctionHandle{new(Listen)}
	case syscall.SYS_MINCORE:
		ret = &FunctionHandle{new(Mincore)}
	case syscall.SYS_MKDIR:
		ret = &FunctionHandle{new(Mkdir)}
	case syscall.SYS_MOUNT:
		ret = &FunctionHandle{new(Mount)}
	case syscall.SYS_MPROTECT:
		ret = &FunctionHandle{new(Mprotect)}
	case syscall.SYS_NANOSLEEP:
		ret = &FunctionHandle{new(Nanosleep)}
	case syscall.SYS_PIVOT_ROOT:
		ret = &FunctionHandle{new(PivotRoot)}
	case syscall.SYS_PRLIMIT64:
		ret = &FunctionHandle{new(Prlimit64)}
	case syscall.SYS_PTRACE:
		ret = &FunctionHandle{new(Ptrace)}
	case syscall.SYS_READ:
		ret = &FunctionHandle{new(Read)}
	case syscall.SYS_READLINK:
		ret = &FunctionHandle{new(Readlink)}
	case syscall.SYS_READLINKAT:
		ret = &FunctionHandle{new(Readlinkat)}
	case syscall.SYS_RECVFROM:
		ret = &FunctionHandle{new(Recvfrom)}
	case syscall.SYS_RENAME:
		ret = &FunctionHandle{new(Rename)}
	case syscall.SYS_RMDIR:
		ret = &FunctionHandle{new(Rmdir)}
	case SYS_SECCOMP:
		ret = &FunctionHandle{new(Seccomp)}
	case syscall.SYS_SENDTO:
		ret = &FunctionHandle{new(Sendto)}
	case SYS_SETNS:
		ret = &FunctionHandle{new(Setns)}
	case syscall.SYS_SETSOCKOPT:
		ret = &FunctionHandle{new(Setsockopt)}
	case syscall.SYS_BIND:
		ret = &FunctionHandle{new(Bind)}
	case syscall.SYS_EXECVE:
		ret = &FunctionHandle{new(Execve)}
	case syscall.SYS_OPEN:
		ret = &FunctionHandle{new(Open)}
	case syscall.SYS_OPENAT:
		ret = &FunctionHandle{new(Openat)}
	case syscall.SYS_CHDIR:
		ret = &FunctionHandle{new(Chdir)}
	case syscall.SYS_CHROOT:
		ret = &FunctionHandle{new(Chroot)}
	case syscall.SYS_ACCESS:
		ret = &FunctionHandle{new(Access)}
	case syscall.SYS_WRITE:
		ret = &FunctionHandle{new(Write)}
	case syscall.SYS_UNLINK:
		ret = &FunctionHandle{new(Unlink)}
	case syscall.SYS_UMOUNT2:
		ret = &FunctionHandle{new(Umount2)}
	case syscall.SYS_TIMERFD_SETTIME:
		ret = &FunctionHandle{new(TimerFDSettime)}
	case syscall.SYS_TIMERFD_CREATE:
		ret = &FunctionHandle{new(TimerFDCreate)}
	case syscall.SYS_SYSLOG:
		ret = &FunctionHandle{new(Syslog)}
	case syscall.SYS_SYMLINK:
		ret = &FunctionHandle{new(Symlink)}
	case syscall.SYS_STATFS:
		ret = &FunctionHandle{new(Statfs)}
	case syscall.SYS_STAT:
		ret = &FunctionHandle{new(Stat)}
	case syscall.SYS_SOCKET:
		ret = &FunctionHandle{new(Socket)}
	case syscall.SYS_SETUID:
		ret = &FunctionHandle{new(Setuid)}
	default:
		return nil, fmt.Errorf("unhandled syscall: %v", nr)
	}

	if err := ret.DecodeArguments(arguments, arglen); err != nil {
		return nil, err
	}

	return ret, nil
}
*/
