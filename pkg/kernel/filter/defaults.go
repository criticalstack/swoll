package filter

func (f *Filter) ApplySyscallDefaults(ns int) error {
	for _, val := range defaultSyscalls {
		if err := f.AddSyscall(val, ns); err != nil {
			return err
		}
	}

	return nil
}

func (f *Filter) ApplyDefaults() error {
	if err := f.FilterSelf(); err != nil {
		return err
	}

	if err := f.ApplySyscallDefaults(0); err != nil {
		return err
	}

	return nil
}

var defaultSyscalls = []string{
	"sys_execve",
	"sys_openat",
	"sys_open",
	"sys_accept",
	"sys_accept4",
	"sys_bind",
	"sys_connect",
	"sys_socket",
	"sys_listen",
	"sys_setns",
	"sys_mkdir",
	"sys_mkdirat",
	"sys_statfs",
	"sys_access",
	"sys_prlimit",
	"sys_mount",
	"sys_unlink",
	"sys_unlinkat",
	"sys_setuid",
	"sys_faccessat",
	"sys_syslog",
	"sys_getcwd",
	"sys_pivot_root",
	"sys_ptrace",
	"sys_chdir",
	"sys_chroot",
	"sys_link",
	"sys_readlink",
	"sys_readlinkat",
	"sys_symlink",
	"sys_getpeername",
	"sys_getsockname",
	"sys_setsockopt",
	"sys_getsockopt",
	"sys_creat",
	"sys_init_module",
	"sys_seccomp",
	"sys_umount2",
	"sys_rmdir",
	"sys_stat",
	"sys_fstat",
	"sys_mknod",
	"sys_rename",
	"sys_timerfd_settime",
	"sys_timerfd_create",
	"sys_mincore",
	"sys_inotify_add_watch",
	"sys_ftruncate",
	"sys_sethostname",
	"sys_ioctl",
	"sys_clone",
	"sys_nanosleep",
	"sys_close",
	"sys_sendto",
	"sys_recvfrom",
	"sys_rt_sigaction",
	"sys_mprotect",
	// "sys_read"
}
