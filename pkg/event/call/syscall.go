package call

import (
	"fmt"
	"syscall"
)

const (
	SYS_SECCOMP = 317
	SYS_SETNS   = 308
)

func DecodeSyscall(nr int, arguments []*byte, arglen int) (Function, error) {
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
