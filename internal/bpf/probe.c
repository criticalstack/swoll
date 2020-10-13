#include <linux/types.h>
#include <linux/socket.h>
#include <linux/version.h>
#include <linux/ptrace.h>
#include <linux/bpf.h>
#include <syscall.h>
#include <linux/utsname.h>
#include <linux/mount.h>
#include <limits.h>
#include <linux/pid.h>

#include "bpf.h"

#ifndef memset
# define memset(dest, chr, n)   __builtin_memset((dest), (chr), (n))
#endif

#ifndef memcpy
# define memcpy(dest, src, n)   __builtin_memcpy((dest), (src), (n))
#endif

#ifndef memmove
# define memmove(dest, src, n)  __builtin_memmove((dest), (src), (n))
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0) && LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
#define randomized_struct_fields_start struct {
#define randomized_struct_fields_end \
};
#endif

#ifndef __PIDTYPE_TGID
#define __PIDTYPE_TGID                 PIDTYPE_MAX + 1
#endif

#define _(P)                                     \
    ({                                           \
        typeof(P) _val;                          \
        memset(&_val, 0, sizeof(_val));          \
        bpf_probe_read(&_val, sizeof(_val), &P); \
        _val;                                    \
    })


#undef SC__DEBUG

#if defined(SC__DEBUG)
#define D_(fmt, ...)                                                \
    ({                                                              \
        char ____fmt[] = fmt;                                       \
        bpf_trace_printk(____fmt, sizeof(____fmt), ## __VA_ARGS__); \
    })
#else
#define D_(fmt, ...)
#endif

#define _(P) ({                                  \
        typeof(P) _val;                          \
        memset(&_val, 0, sizeof(_val));          \
        bpf_probe_read(&_val, sizeof(_val), &P); \
        _val;                                    \
    })


#define _inline                        inline __attribute__((always_inline))

struct __args_common {
    __u16 type;
    __u8  flags;
    __u8  preempt;
    __s32 pid;
};

struct on_enter_args {
    long          id;
    unsigned long args[6];
};

struct on_exit_args {
    long id;
    long ret;
};

#define FARGS_STRUCT_DEF(TYPE) struct __args_ ## TYPE
#define FARGS_STRUCT(TYPE)     FARGS_STRUCT_DEF(TYPE) TYPE


/*
 * field:int __syscall_nr; offset:8;       size:4; signed:1;
 * field:pid_t pid;        offset:16;      size:8; signed:0;
 * field:int sig;  offset:24;      size:8; signed:0;
 */
FARGS_STRUCT_DEF(kill) {
    __s32 nr;
    __u64 pid;
    __u64 sig;
};

/*
 * field:int __syscall_nr; offset:8;       size:4; signed:1;
 * field:const char * name;        offset:16;      size:8; signed:0;
 */
FARGS_STRUCT_DEF(acct) {
    __s32        nr;
    const char * pathname;
};
/*
 * field:int __syscall_nr; offset:8;       size:4; signed:1;
 * field:unsigned int seconds;     offset:16;      size:8; signed:0;
 */
FARGS_STRUCT_DEF(alarm) {
    __s32 nr;
    __u64 seconds;
};

/*
 *     field:int __syscall_nr; offset:8;       size:4; signed:1;
 *     field:unsigned long brk;        offset:16;      size:8; signed:0;
 *     */
FARGS_STRUCT_DEF(brk) {
    __s32 nr;
    __u64 addr;
};

/*
 *  field:int __syscall_nr;	offset:8;	size:4;	signed:1;
 *      field:const char * pathname;	offset:16;	size:8;	signed:0;
 *      field:struct statfs * buf;	offset:24;	size:8;	signed:0;
 */
FARGS_STRUCT_DEF(statfs) {
    __s32           nr;
    const char    * pathname;
    struct statfs * buf;
};

/*
 *      field:int __syscall_nr;	offset:8;	size:4;	signed:1;
 *      field:unsigned int fd;	offset:16;	size:8;	signed:0;
 *      field:struct stat * statbuf;	offset:24;	size:8;	signed:0;
 */

FARGS_STRUCT_DEF(fstat) {
    __u32         nr;
    __u64         fd;
    struct stat * statbuf;
};


FARGS_STRUCT_DEF(stat) {
    __u32         nr;
    const char  * filename;
    struct stat * statbuf;
};

/*
 *  field:int __syscall_nr;	offset:8;	size:4;	signed:1;
 *      field:char * dev_name;	offset:16;	size:8;	signed:0;
 *      field:char * dir_name;	offset:24;	size:8;	signed:0;
 *      field:char * type;	offset:32;	size:8;	signed:0;
 *      field:unsigned long flags;	offset:40;	size:8;	signed:0;
 *      field:void * data;	offset:48;	size:8;	signed:0;
 */

FARGS_STRUCT_DEF(mount) {
    __u32  nr;
    char * dev_name;
    char * dir_name;
    char * type;
    __u64  flags;
    void * data;
};

/*
 *      field:int __syscall_nr;	offset:8;	size:4;	signed:1;
 *      field:char * name;	offset:16;	size:8;	signed:0;
 *      field:int flags;	offset:24;	size:8;	signed:0;
 */
FARGS_STRUCT_DEF(umount2) {
    __u32  nr;
    char * name;
    __u64  flags;
};


FARGS_STRUCT_DEF(openat) {
    __s32   nr;
    __s64   dfd;
    __u64 * filename;
    __u64   flags;
    __u64   mode;
};

FARGS_STRUCT_DEF(open) {
    __u32   nr;
    __u64 * filename;
    __s64   flags;
    __u64   mode;
};

FARGS_STRUCT_DEF(connect) {
    __u32  nr;
    __s64  fd;
    void * uservaddr;
    __u64  addrlen;
};


FARGS_STRUCT_DEF(execve) {
    __u32   nr;
    char  * filename;
    char ** argv;
    char ** envp;
};

FARGS_STRUCT_DEF(bind) {
    __u32             nr;
    __u64             fd;
    struct sockaddr * umyaddr;
    __u64             addrlen;
};


FARGS_STRUCT_DEF(sched_process_fork) {
    char  parent_comm[16];
    pid_t parent_pid;
    char  child_comm[16];
    pid_t child_pid;
};

FARGS_STRUCT_DEF(unlink) {
    __u32  nr;
    char * pathname;
};


FARGS_STRUCT_DEF(epoll_wait) {
    __u32                nr;
    __u64                epfd;
    struct epoll_event * events;
    __u64                maxevents;
    __u64                timeout;
};


FARGS_STRUCT_DEF(unlinkat) {
    __u32  nr;
    __u64  dfd;
    char * pathname;
    __u64  offset;
};

/*
 *      field:int __syscall_nr;	offset:8;	size:4;	signed:1;
 *      field:unsigned long addr;	offset:16;	size:8;	signed:0;
 *      field:unsigned long len;	offset:24;	size:8;	signed:0;
 *      field:unsigned long prot;	offset:32;	size:8;	signed:0;
 *      field:unsigned long flags;	offset:40;	size:8;	signed:0;
 *      field:unsigned long fd;	offset:48;	size:8;	signed:0;
 *      field:unsigned long off;	offset:56;	size:8;	signed:0;
 */

FARGS_STRUCT_DEF(mmap) {
    __u32 nr;
    __u64 addr;
    __u64 len;
    __u64 prot;
    __u64 flags;
    __u64 fd;
    __u64 off;
};


FARGS_STRUCT_DEF(faccessat) {
    __u32  nr;
    __u64  dfd;
    char * filename;
    __u64  mode;
};

FARGS_STRUCT_DEF(access) {
    __u32        nr;
    const char * filename;
    __u64        mode;
};

FARGS_STRUCT_DEF(statx) {
    __u32          nr;
    __u64          dfd;
    char         * filename;
    __u64          flags;
    __u64          mask;
    struct statx * buffer;
};

FARGS_STRUCT_DEF(syslog) {
    __u32  nr;
    __u64  type;
    char * buf;
    __s64  len;
};

FARGS_STRUCT_DEF(fcntl) {
    __u32 nr;
    __s64 fd;
    __s64 cmd;
    __u64 arg;
};

FARGS_STRUCT_DEF(fdatasync) {
    __u32 nr;
    __u64 fd;
};

FARGS_STRUCT_DEF(fstatfs) {
    __u32           nr;
    __u64           fd;
    struct statfs * buf;
};

FARGS_STRUCT_DEF(fsync) {
    __u32 nr;
    __u64 fd;
};

FARGS_STRUCT_DEF(getcwd) {
    __u32  nr;
    char * buf;
    __u64  size;
};

FARGS_STRUCT_DEF(getdents) {
    __u32                 nr;
    __u64                 fd;
    struct linux_dirent * dirent;
    __u64                 count;
};

FARGS_STRUCT_DEF(inotify_add_watch) {
    __u32  nr;
    __u64  fd;
    char * pathname;
    __u64  mask;
};

FARGS_STRUCT_DEF(listen) {
    __u32 nr;
    __u64 fd;
    __u64 backlog;
};

FARGS_STRUCT_DEF(lookup_dcookie) {
    __u32  nr;
    __u64  cookie64;
    char * buf;
    __u64  len;
};

FARGS_STRUCT_DEF(lseek) {
    __u32 nr;
    __u64 fd;
    __u64 offset;
    __u64 whence;
};

FARGS_STRUCT_DEF(madvise) {
    __u32 nr;
    __u64 start;
    __u64 len_in;
    __u64 behavior;
};

FARGS_STRUCT_DEF(membarrier) {
    __u32 nr;
    __u64 cmd;
    __u64 flags;
};

FARGS_STRUCT_DEF(migrate_pages) {
    __u32   nr;
    __u64   pid;
    __u64   maxnode;
    __u64 * old_nodes;
    __u64 * new_nodes;
};

FARGS_STRUCT_DEF(mkdir) {
    __u32  nr;
    char * pathname;
    __u64  mode;
};

FARGS_STRUCT_DEF(mkdirat) {
    __u32  nr;
    __u64  dfd;
    char * pathname;
    __u64  mode;
};

FARGS_STRUCT_DEF(mknod) {
    __u32  nr;
    char * filename;
    __u64  mode;
    __u64  dev;
};

FARGS_STRUCT_DEF(mlock) {
    __u32 nr;
    __u64 start;
    __u64 len;
};

FARGS_STRUCT_DEF(pivot_root) {
    __u32  nr;
    char * new_root;
    char * put_old;
};

FARGS_STRUCT_DEF(poll) {
    __u32           nr;
    struct pollfd * ufds;
    __u64           nfds;
    __u64           timeout_msecs;
};

/*
 *  field:int __syscall_nr;	offset:8;	size:4;	signed:1;
 *      field:int fd;	offset:16;	size:8;	signed:0;
 *      field:int nstype;	offset:24;	size:8;	signed:0;
 */

FARGS_STRUCT_DEF(setns) {
    __s32 nr;
    __u64 fd;
    __u64 nstype;
};

/*
 *  field:int __syscall_nr;	offset:8;	size:4;	signed:1;
 *      field:int family;	offset:16;	size:8;	signed:0;
 *      field:int type;	offset:24;	size:8;	signed:0;
 *      field:int protocol;	offset:32;	size:8;	signed:0;
 */
FARGS_STRUCT_DEF(socket) {
    __s32 nr;
    __u64 family;
    __u64 type;
    __u64 protocol;
};


FARGS_STRUCT_DEF(prctl) {
    __u32 nr;
    __u64 option;
    __u64 arg2;
    __u64 arg3;
    __u64 arg4;
    __u64 arg5;
};

/*
 *  field:int __syscall_nr;	offset:8;	size:4;	signed:1;
 *      field:pid_t pid;	offset:16;	size:8;	signed:0;
 *      field:unsigned int resource;	offset:24;	size:8;	signed:0;
 *      field:const struct rlimit64 * new_rlim;	offset:32;	size:8;	signed:0;
 *      field:struct rlimit64 * old_rlim;	offset:40;	size:8;	signed:0;
 */
FARGS_STRUCT_DEF(prlimit64) {
    __u32                   nr;
    __u64                   pid;
    __u64                   resource;
    const struct rlimit64 * new_rlim;
    struct rlimit64       * old_rlim;
};

/*
 *  field:int __syscall_nr;	offset:8;	size:4;	signed:1;
 *      field:int fd;	offset:16;	size:8;	signed:0;
 *      field:struct user_msghdr * msg;	offset:24;	size:8;	signed:0;
 *      field:unsigned int flags;	offset:32;	size:8;	signed:0;
 */
FARGS_STRUCT_DEF(recvmsg) {
    __u32                nr;
    __s64                fd;
    struct user_msghdr * msg;
    __u64                flags;
};


/*
 *  field:int __syscall_nr;	offset:8;	size:4;	signed:1;
 *      field:int fd;	offset:16;	size:8;	signed:0;
 *      field:void * buff;	offset:24;	size:8;	signed:0;
 *      field:size_t len;	offset:32;	size:8;	signed:0;
 *      field:unsigned int flags;	offset:40;	size:8;	signed:0;
 *      field:struct sockaddr * addr;	offset:48;	size:8;	signed:0;
 *      field:int addr_len;	offset:56;	size:8;	signed:0;
 */
FARGS_STRUCT_DEF(sendto) {
    __u32             nr;
    __u64             fd;
    void            * ubuf;
    __u64             size;
    __u64             flags;
    struct sockaddr * addr;
    __u64             addr_len;
};


/*
 * field:int __syscall_nr;	offset:8;	size:4;	signed:1;
 *      field:int fd;	offset:16;	size:8;	signed:0;
 *      field:void * ubuf;	offset:24;	size:8;	signed:0;
 *      field:size_t size;	offset:32;	size:8;	signed:0;
 *      field:unsigned int flags;	offset:40;	size:8;	signed:0;
 *      field:struct sockaddr * addr;	offset:48;	size:8;	signed:0;
 *      field:int * addr_len;	offset:56;	size:8;	signed:0;
 */

FARGS_STRUCT_DEF(recvfrom) {
    __u32             nr;
    __u64             fd;
    void            * ubuf;
    __u64             size;
    __u64             flags;
    struct sockaddr * addr;
    __u64           * addr_len;
};

/*
 *
 *      field:int __syscall_nr;	offset:8;	size:4;	signed:1;
 *      field:uid_t uid;	offset:16;	size:8;	signed:0;
 */
FARGS_STRUCT_DEF(setuid) {
    __u32 nr;
    __u64 uid;
};

/*
 *      field:int __syscall_nr;	offset:8;	size:4;	signed:1;
 *      field:uid_t ruid;	offset:16;	size:8;	signed:0;
 *      field:uid_t euid;	offset:24;	size:8;	signed:0;
 */
FARGS_STRUCT_DEF(setreuid) {
    __u32 nr;
    __u64 ruid;
    __u64 euid;
};

/*
 *      field:int __syscall_nr;	offset:8;	size:4;	signed:1;
 *      field:unsigned int fd;	offset:16;	size:8;	signed:0;
 */
FARGS_STRUCT_DEF(close) {
    __u32 nr;
    __u64 fd;
};


/*
 *  field:int __syscall_nr;	offset:8;	size:4;	signed:1;
 *      field:const char * pathname;	offset:16;	size:8;	signed:0;
 */

FARGS_STRUCT_DEF(rmdir) {
    __u32        nr;
    const char * pathname;
};


/*
 *      field:int __syscall_nr;	offset:8;	size:4;	signed:1;
 *      field:long request;	offset:16;	size:8;	signed:0;
 *      field:long pid;	offset:24;	size:8;	signed:0;
 *      field:unsigned long addr;	offset:32;	size:8;	signed:0;
 *      field:unsigned long data;	offset:40;	size:8;	signed:0;
 */
FARGS_STRUCT_DEF(ptrace) {
    __u32 nr;
    __u64 request;
    __u64 pid;
    __u64 addr;
    __u64 data;
};


/*
 *  field:int __syscall_nr;	offset:8;	size:4;	signed:1;
 *      field:const char * filename;	offset:16;	size:8;	signed:0;
 */
FARGS_STRUCT_DEF(chdir) {
    __u32        nr;
    const char * filename;
};


FARGS_STRUCT_DEF(chroot) {
    __u32        nr;
    const char * filename;
};


/*
 *  field:int __syscall_nr;	offset:8;	size:4;	signed:1;
 *      field:const char * oldname;	offset:16;	size:8;	signed:0;
 *      field:const char * newname;	offset:24;	size:8;	signed:0;
 */
FARGS_STRUCT_DEF(link) {
    __u32        nr;
    const char * oldname;
    const char * newname;
};

/*
 *
 *      field:int __syscall_nr;	offset:8;	size:4;	signed:1;
 *      field:const char * path;	offset:16;	size:8;	signed:0;
 *      field:char * buf;	offset:24;	size:8;	signed:0;
 *      field:int bufsiz;	offset:32;	size:8;	signed:0;
 */

FARGS_STRUCT_DEF(readlink) {
    __u32        nr;
    const char * path;
    char       * buf;
    __u64        bufsiz;
};

/*
 *  field:int __syscall_nr;	offset:8;	size:4;	signed:1;
 *      field:int dfd;	offset:16;	size:8;	signed:0;
 *      field:const char * pathname;	offset:24;	size:8;	signed:0;
 *      field:char * buf;	offset:32;	size:8;	signed:0;
 *      field:int bufsiz;	offset:40;	size:8;	signed:0;
 */

FARGS_STRUCT_DEF(readlinkat) {
    __u32        nr;
    __u64        dfd;
    const char * pathname;
    char       * buf;
    __u64        bufsiz;
};



/*  field:int __syscall_nr;	offset:8;	size:4;	signed:1;
 *      field:const char * oldname;	offset:16;	size:8;	signed:0;
 *      field:const char * newname;	offset:24;	size:8;	signed:0;
 */

FARGS_STRUCT_DEF(symlink) {
    __u32        nr;
    const char * oldname;
    const char * newname;
};

/*
 *
 *      field:int __syscall_nr;	offset:8;	size:4;	signed:1;
 *      field:int fd;	offset:16;	size:8;	signed:0;
 *      field:struct sockaddr * usockaddr;	offset:24;	size:8;	signed:0;
 *      field:int * usockaddr_len;	offset:32;	size:8;	signed:0;
 */
FARGS_STRUCT_DEF(getpeername) {
    __u32             nr;
    __u64             fd;
    struct sockaddr * usockaddr;
    __u64           * usockaddr_len;
};


/*
 *      field:int __syscall_nr;	offset:8;	size:4;	signed:1;
 *      field:int fd;	offset:16;	size:8;	signed:0;
 *      field:struct sockaddr * usockaddr;	offset:24;	size:8;	signed:0;
 *      field:int * usockaddr_len;	offset:32;	size:8;	signed:0;
 */

FARGS_STRUCT_DEF(getsockname) {
    __u32             nr;
    __u64             fd;
    struct sockaddr * usockaddr;
    __u64             usockaddr_len;
};

/*
 *      field:int __syscall_nr;	offset:8;	size:4;	signed:1;
 *      field:int fd;	offset:16;	size:8;	signed:0;
 *      field:struct sockaddr * upeer_sockaddr;	offset:24;	size:8;	signed:0;
 *      field:int * upeer_addrlen;	offset:32;	size:8;	signed:0;
 *  field:int flags;	offset:40;	size:8;	signed:0;
 *
 */
FARGS_STRUCT_DEF(accept) {
    __u32             nr;
    __u64             fd;
    struct sockaddr * saddr;
    __u64           * saddr_len;
    __u64             flags;
};


/*
 *      field:int __syscall_nr;	offset:8;	size:4;	signed:1;
 *      field:unsigned long start;	offset:16;	size:8;	signed:0;
 *      field:size_t len;	offset:24;	size:8;	signed:0;
 *      field:unsigned long prot;	offset:32;	size:8;	signed:0;
 */
FARGS_STRUCT_DEF(mprotect) {
    __u32 nr;
    __u64 start;
    __u64 len;
    __u64 prot;
};

/*
 *      field:int __syscall_nr;	offset:8;	size:4;	signed:1;
 *      field:int fd;	offset:16;	size:8;	signed:0;
 *      field:int level;	offset:24;	size:8;	signed:0;
 *      field:int optname;	offset:32;	size:8;	signed:0;
 *      field:char * optval;	offset:40;	size:8;	signed:0;
 *      field:int optlen;	offset:48;	size:8;	signed:0;
 */
FARGS_STRUCT_DEF(setsockopt) {
    __u32  nr;
    __u64  fd;
    __u64  level;
    __u64  optname;
    char * optval;
    __u64  optlen;
};

/*
 *      field:int __syscall_nr;	offset:8;	size:4;	signed:1;
 *      field:int fd;	offset:16;	size:8;	signed:0;
 *      field:int level;	offset:24;	size:8;	signed:0;
 *      field:int optname;	offset:32;	size:8;	signed:0;
 *      field:char * optval;	offset:40;	size:8;	signed:0;
 *      field:int * optlen;	offset:48;	size:8;	signed:0;
 */
FARGS_STRUCT_DEF(getsockopt) {
    __u32   nr;
    __u64   fd;
    __u64   level;
    __u64   optname;
    char  * optval;
    __u64 * optlen;
};


/*
 *      field:int __syscall_nr;	offset:8;	size:4;	signed:1;
 *      field:const char * pathname;	offset:16;	size:8;	signed:0;
 *      field:umode_t mode;	offset:24;	size:8;	signed:0;
 */
FARGS_STRUCT_DEF(creat) {
    __u32        nr;
    const char * pathname;
    __u64        mode;
};

/*
 *      field:int __syscall_nr;	offset:8;	size:4;	signed:1;
 *      field:void * umod;	offset:16;	size:8;	signed:0;
 *      field:unsigned long len;	offset:24;	size:8;	signed:0;
 *      field:const char * uargs;	offset:32;	size:8;	signed:0;
 */
FARGS_STRUCT_DEF(init_module) {
    __u32   nr;
    void  * umod;
    __u64   len;
    __u64 * uargs;
};

/*
 *      field:int __syscall_nr;	offset:8;	size:4;	signed:1;
 *      field:unsigned int op;	offset:16;	size:8;	signed:0;
 *      field:unsigned int flags;	offset:24;	size:8;	signed:0;
 *      field:const char * uargs;	offset:32;	size:8;	signed:0;
 */
FARGS_STRUCT_DEF(seccomp) {
    __u32        nr;
    __u64        op;
    __u64        flags;
    const char * uargs;
};

/*
 *      field:char * name;	offset:16;	size:8;	signed:0;
 *      field:int len;	offset:24;	size:8;	signed:0;
 */
FARGS_STRUCT_DEF(sethostname) {
    __u32  nr;
    char * name;
    __u64  len;
};

/*
 *      field:int __syscall_nr;	offset:8;	size:4;	signed:1;
 *      field:unsigned long clone_flags;	offset:16;	size:8;	signed:0;
 *      field:unsigned long newsp;	offset:24;	size:8;	signed:0;
 *      field:int * parent_tidptr;	offset:32;	size:8;	signed:0;
 *      field:int * child_tidptr;	offset:40;	size:8;	signed:0;
 *      field:unsigned long tls;	offset:48;	size:8;	signed:0;
 */

FARGS_STRUCT_DEF(clone) {
    __u32   nr;
    __u64   flags;
    __u64   newsp;
    __u64 * parent_tidptr;
    __u64 * child_tidptr;
    __u64   tls;
};


/*
 *      field:int __syscall_nr;	offset:8;	size:4;	signed:1;
 *      field:unsigned int fd;	offset:16;	size:8;	signed:0;
 *      field:char * buf;	offset:24;	size:8;	signed:0;
 *      field:size_t count;	offset:32;	size:8;	signed:0;
 */
FARGS_STRUCT_DEF(read) {
    __u32  nr;
    __u64  fd;
    char * buf;
    __u64  count;
};

/*
 *      field:int __syscall_nr;	offset:8;	size:4;	signed:1;
 *      field:unsigned int fd;	offset:16;	size:8;	signed:0;
 *      field:unsigned int cmd;	offset:24;	size:8;	signed:0;
 *      field:unsigned long arg;	offset:32;	size:8;	signed:0;
 */
FARGS_STRUCT_DEF(ioctl) {
    __u32 nr;
    __u64 fd;
    __u64 cmd;
    __u64 arg;
};

/*
 *      field:int __syscall_nr;	offset:8;	size:4;	signed:1;
 *      field:const char * oldname;	offset:16;	size:8;	signed:0;
 *      field:const char * newname;	offset:24;	size:8;	signed:0;
 */
FARGS_STRUCT_DEF(rename) {
    __u32        nr;
    const char * oldname;
    const char * newname;
};

/*
 *      field:int __syscall_nr;	offset:8;	size:4;	signed:1;
 *      field:int ufd;	offset:16;	size:8;	signed:0;
 *      field:int flags;	offset:24;	size:8;	signed:0;
 *      field:const struct itimerspec * utmr;	offset:32;	size:8;	signed:0;
 *      field:struct itimerspec * otmr;	offset:40;	size:8;	signed:0;
 */

FARGS_STRUCT_DEF(timerfd_settime) {
    __u32                     nr;
    __u64                     flags;
    __u64                     ufd;
    const struct itimerspec * utmr;
    struct itimerspec       * otmr;
};

/*
 *      field:int __syscall_nr;	offset:8;	size:4;	signed:1;
 *      field:int clockid;	offset:16;	size:8;	signed:0;
 *      field:int flags;	offset:24;	size:8;	signed:0;
 */
FARGS_STRUCT_DEF(timerfd_create) {
    __u32 nr;
    __u64 clockid;
    __u64 flags;
};


/*
 *      field:int __syscall_nr;	offset:8;	size:4;	signed:1;
 *      field:unsigned long start;	offset:16;	size:8;	signed:0;
 *      field:size_t len;	offset:24;	size:8;	signed:0;
 *      field:unsigned char * vec;	offset:32;	size:8;	signed:0;
 */
FARGS_STRUCT_DEF(mincore)
{
    __u32           nr;
    __u64           start;
    __u64           len;
    unsigned char * vec;
};

/*
 *      field:int __syscall_nr;	offset:8;	size:4;	signed:1;
 *      field:unsigned int fd;	offset:16;	size:8;	signed:0;
 *      field:unsigned long length;	offset:24;	size:8;	signed:0;
 */
FARGS_STRUCT_DEF(ftruncate)
{
    __u32 nr;
    __u64 fd;
    __u64 length;
};


/*
 *      field:int __syscall_nr;	offset:8;	size:4;	signed:1;
 *      field:struct timespec * rqtp;	offset:16;	size:8;	signed:0;
 *      field:struct timespec * rmtp;	offset:24;	size:8;	signed:0;
 */
FARGS_STRUCT_DEF(nanosleep)
{
    __u32             nr;
    struct timespec * rqtp;
    struct timespec * rmtp;
};


/*
 *  field:int __syscall_nr;	offset:8;	size:4;	signed:1;
 *      field:int sig;	offset:16;	size:8;	signed:0;
 *      field:const struct sigaction * act;	offset:24;	size:8;	signed:0;
 *      field:struct sigaction * oact;	offset:32;	size:8;	signed:0;
 *      field:size_t sigsetsize;	offset:40;	size:8;	signed:0;
 */
FARGS_STRUCT_DEF(rt_sigaction) {
    __u32              nr;
    __u64              sig;
    struct sigaction * act;
    struct sigaction * oact;
    __u64              sigsetsize;
};


/*
 *      field:int __syscall_nr;	offset:8;	size:4;	signed:1;
 *      field:unsigned int fd;	offset:16;	size:8;	signed:0;
 *      field:const char * buf;	offset:24;	size:8;	signed:0;
 *      field:size_t count;	offset:32;	size:8;	signed:0;
 */
FARGS_STRUCT_DEF(write)
{
    __u32        nr;
    __u64        fd;
    const char * buf;
    __u64        count;
};

/*
 *      field:int __syscall_nr;	offset:8;	size:4;	signed:1;
 *      field:u32 * uaddr;	offset:16;	size:8;	signed:0;
 *      field:int op;	offset:24;	size:8;	signed:0;
 *      field:u32 val;	offset:32;	size:8;	signed:0;
 *      field:struct timespec * utime;	offset:40;	size:8;	signed:0;
 *      field:u32 * uaddr2;	offset:48;	size:8;	signed:0;
 *      field:u32 val3;	offset:56;	size:8;	signed:0;
 */
FARGS_STRUCT_DEF(futex) {
    __u32             nr;
    __u64           * uaddr;
    __u64             op;
    __u64             val;
    struct timespec * utime;
    __u64           * uaddr2;
    __u64             val3;
};

FARGS_STRUCT_DEF(select)
{
    __u32            nr;
    __u64            n;
    fd_set         * inp;
    fd_set         * outp;
    fd_set         * exp;
    struct timeval * tvp;
};


/*
 *      field:int __syscall_nr;	offset:8;	size:4;	signed:1;
 *      field:int error_code;	offset:16;	size:8;	signed:0;
 */

FARGS_STRUCT_DEF(exit)
{
    __u32 nr;
    __u64 error_code;
};

struct __args {
    struct __args_common common;

    union {
        struct on_enter_args on_enter;
        struct on_exit_args  on_exit;
        FARGS_STRUCT(kill);
        FARGS_STRUCT(setuid);
        FARGS_STRUCT(setreuid);
        FARGS_STRUCT(recvmsg);
        FARGS_STRUCT(recvfrom);
        FARGS_STRUCT(sendto);
        FARGS_STRUCT(access);
        FARGS_STRUCT(mount);
        FARGS_STRUCT(bind);
        FARGS_STRUCT(socket);
        FARGS_STRUCT(openat);
        FARGS_STRUCT(open);
        FARGS_STRUCT(connect);
        FARGS_STRUCT(execve);
        FARGS_STRUCT(unlink);
        FARGS_STRUCT(unlinkat);
        FARGS_STRUCT(epoll_wait);
        FARGS_STRUCT(faccessat);
        FARGS_STRUCT(statx);
        FARGS_STRUCT(syslog);
        FARGS_STRUCT(fcntl);
        FARGS_STRUCT(fdatasync);
        FARGS_STRUCT(fstatfs);
        FARGS_STRUCT(fstat);
        FARGS_STRUCT(stat);
        FARGS_STRUCT(statfs);
        FARGS_STRUCT(acct);
        FARGS_STRUCT(alarm);
        FARGS_STRUCT(brk);
        FARGS_STRUCT(fsync);
        FARGS_STRUCT(ftruncate);
        FARGS_STRUCT(getcwd);
        FARGS_STRUCT(getdents);
        FARGS_STRUCT(listen);
        FARGS_STRUCT(lseek);
        FARGS_STRUCT(mkdir);
        FARGS_STRUCT(mkdirat);
        FARGS_STRUCT(mknod);
        FARGS_STRUCT(mlock);
        FARGS_STRUCT(madvise);
        FARGS_STRUCT(membarrier);
        FARGS_STRUCT(pivot_root);
        FARGS_STRUCT(poll);
        FARGS_STRUCT(prctl);
        FARGS_STRUCT(migrate_pages);
        FARGS_STRUCT(lookup_dcookie);
        FARGS_STRUCT(sched_process_fork);
        FARGS_STRUCT(inotify_add_watch);
        FARGS_STRUCT(close);
        FARGS_STRUCT(rmdir);
        FARGS_STRUCT(ptrace);
        FARGS_STRUCT(chdir);
        FARGS_STRUCT(chroot);
        FARGS_STRUCT(link);
        FARGS_STRUCT(readlink);
        FARGS_STRUCT(symlink);
        FARGS_STRUCT(getpeername);
        FARGS_STRUCT(getsockname);
        FARGS_STRUCT(accept);
        FARGS_STRUCT(mprotect);
        FARGS_STRUCT(setsockopt);
        FARGS_STRUCT(getsockopt);
        FARGS_STRUCT(creat);
        FARGS_STRUCT(init_module);
        FARGS_STRUCT(seccomp);
        FARGS_STRUCT(umount2);
        FARGS_STRUCT(sethostname);
        FARGS_STRUCT(clone);
        FARGS_STRUCT(read);
        FARGS_STRUCT(write);
        FARGS_STRUCT(ioctl);
        FARGS_STRUCT(rename);
        FARGS_STRUCT(timerfd_settime);
        FARGS_STRUCT(timerfd_create);
        FARGS_STRUCT(mincore);
        FARGS_STRUCT(nanosleep);
        FARGS_STRUCT(rt_sigaction);
        FARGS_STRUCT(futex);
        FARGS_STRUCT(select);
        FARGS_STRUCT(exit);
    };
};

struct sk_event_key {
    struct on_enter_args on_enter;
    __u64                uid_gid;
    __u64                entr_timestamp;
};

struct sk_metrics_key {
    __u32 pid_ns;  /* The PID namespace that this metric belongs to */
    __u32 mnt_ns;  /* The MNT namespace this belongs to */
    __u32 syscall; /* Syscall NR */
    __u16 error;   /* Errno of the syscall (if non-zero) */
    __u16 pad;     /* for alignment */
};

struct sk_metrics_val {
    __u64 count;      /* total count for this metric */
    __u64 time;       /* total time (in nanoseconds) spent executing this */
    __u64 first_seen; /* unix epoch of the first time this was seen */
    __u64 last_seen;  /* unix epoch of the last time this was seen */
    __u64 _enter_ktime;
};

#define EVENT_ARGSZ   128
#define EVENT_ARGNUM  5
#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

struct sk_args {
    __u8 a0[EVENT_ARGSZ];
    __u8 a1[EVENT_ARGSZ];
    __u8 a2[EVENT_ARGSZ];
    __u8 a3[EVENT_ARGSZ];
    __u8 a4[EVENT_ARGSZ];
};

struct sk_buff {
    __u8  buf[(EVENT_ARGSZ * EVENT_ARGNUM) - sizeof(uint32_t)];
    __u16 len;
    __u16 offset;
};

struct sk_event {
    __u64 pid_tid;
    __u64 uid_gid;
    __u32 syscall;
    __u32 ns_pid;
    __u64 entr_usec;
    __u64 exit_usec;
    __s32 session_id;
    __u32 pid_ns;
    __u32 uts_ns;
    __u32 mnt_ns;
    __u32 ipc_ns;
    __u32 cgr_ns;
    __u64 context_sw;
    __u32 errno;
    __u32 ret;
    __u8  comm[TASK_COMM_LEN];
    union {
        struct sk_args _args;
        struct sk_buff _buff;
    };
};

/* we only want to memset 0 out the byte NOT INCLUDING
 * the argument and comm arguments. Those we can just
 * zero out the first byte of each.
 */
#define BASE_EVENT_SZ sizeof(struct sk_event) - (EVENT_ARGSZ * EVENT_ARGNUM) - TASK_COMM_LEN

struct mnt_namespace {
    int              count;
    struct ns_common ns;
};

struct cgroup_namespace {
    int              count;
    struct ns_common ns;
};

struct ipc_namespace {
    int              count;
    struct ns_common ns;
};

struct bpf_map_def
SEC("maps/sk_metrics") sk_metrics =
{
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = sizeof(struct sk_metrics_key),
    .value_size  = sizeof(struct sk_metrics_val),
    .max_entries = 65535,
};


/**
 * sysk_evtable is where we emit sc_events to.
 */
struct bpf_map_def
SEC("maps/sk_perf_output") sk_perf_output =
{
    .type        = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size    = sizeof(__u32),
    .value_size  = sizeof(__u32),
    .max_entries = 2048,
    .pinning     = 0,
};

struct bpf_map_def
SEC("maps/sk_state_map") sk_state_map =
{
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = sizeof(__u64),
    .value_size  = sizeof(struct sk_event_key),
    .max_entries = 65535,
};


/**
 * @brief since we are limited to PAGE_SIZE of byte
 *        for stack-based memory, we want to extend
 *        the size via PER_CPU-stacks. This is our
 *        "scratch" memory which is used to fetch a
 *        slab upon entry, and stored and released
 *        upon exit.
 *
 * @param "maps/sk_event_scratch"
 *
 * @return
 */
struct bpf_map_def
SEC("maps/sk_event_scratch") sk_event_scratch =
{
    .type        = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size    = sizeof(__u32),
    .value_size  = sizeof(struct sk_event),
    .max_entries = 1024,
};


#define SK_FILTER_MODE_WHITELIST        (1 << 0)
#define SK_FILTER_MODE_BLACKLIST        (1 << 1)
#define SK_FILTER_MODE_GLOBAL_WHITELIST (1 << 2)
#define SK_FILTER_MODE_GLOBAL_BLACKLIST (1 << 3)
#define SK_FILTER_TYPE_SYSCALL          (1 << 13)
#define SK_FILTER_TYPE_PID              (1 << 14)
#define SK_FILTER_TYPE_PIDNS            (1 << 15)

#define SK_FILTER_ALLOW                 0
#define SK_FILTER_DROP                  1

typedef __u16 sk_ftype_t;
typedef __u8  sk_offscfg_t;


struct sk_filter_key {
    sk_ftype_t type; /* FILTER_TYPE_X|BL/WL */
    __u16      pad;
    __u32      ns;   /* optional PID namespace */
    __u32      key;
};

/*
 * #define SEC(NAME) __attribute__((section(NAME), used)
 * struct bpf_map_def __attribute__((section("maps/sk_filter"), sk_filter =...
 */
struct bpf_map_def
SEC("maps/sk_filter") sk_filter =
{
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = sizeof(struct sk_filter_key),
    .value_size  = sizeof(__u8), /* DROP/ALLOW */
    .max_entries = 65535,
};

struct bpf_map_def
SEC("maps/sk_filter_config") sk_filter_config =
{
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = sizeof(sk_ftype_t),
    .value_size  = sizeof(__u8),
    .max_entries = 1024,
};

struct bpf_map_def
SEC("maps/sk_offsets_config") sk_offsets_config =
{
    .type        = BPF_MAP_TYPE_HASH,
    #define SK_OSCFG_NSPROXY     1
    #define SK_OSCFG_PIDNS       2
    .key_size    = sizeof(sk_offscfg_t),
    .value_size  = sizeof(__u32),
    .max_entries = 2,
};

static _inline int
sysk__is_filter_enabled(sk_ftype_t type)
{
    __u8 * val = 0;

    if ((val = bpf_map_lookup_elem(&sk_filter_config, &type))) {
        return *val == 0 ? 0 : 1;
    }

    return 0;
}

static _inline __u32
sysk__get_nsproxy_offset(void)
{
    __u32            * val  = 0;
    sk_offscfg_t const nspc = SK_OSCFG_NSPROXY;

    if ((val = bpf_map_lookup_elem(&sk_offsets_config, &nspc))) {
        return *val;
    }

    return (__u32)offsetof(struct task_struct, nsproxy);
}

static _inline __u32
sysk__get_pid_ns_common_offset(void)
{
    __u32            * val  = 0;
    sk_offscfg_t const nsof = SK_OSCFG_PIDNS;

    if ((val = bpf_map_lookup_elem(&sk_offsets_config, &nsof))) {
        return *val;
    }

    return (__u32)offsetof(struct pid_namespace, ns);
}

static _inline __u8
sysk__eval_filter(sk_ftype_t type, __u32 ns, __u32 key)
{
    if (sysk__is_filter_enabled(type)) {
        struct sk_filter_key fkey = {
            .type = type,
            .pad  = 0,
            .ns   = ns,
            .key  = key,
        };

        /*D_("type=%u, ns=%u, key=%u\n", type, ns, key); */

        if (bpf_map_lookup_elem(&sk_filter, &fkey) != NULL) {
            /* if the value was found in the table, and the lookup type is
             * a WHITELIST, then allow this. Otherwise, if the value was found
             * in the table, but the type is of BLACKLIST, then drop it.
             */
            return (type & (SK_FILTER_MODE_GLOBAL_WHITELIST | SK_FILTER_MODE_WHITELIST)) ?
                   SK_FILTER_ALLOW : SK_FILTER_DROP;
        }

        /* the value was NOT found in the table, so if it is of the type BLACKLIST,
         * we allow it (no entry in the blacklist table).
         */
        return (type & (SK_FILTER_MODE_GLOBAL_BLACKLIST | SK_FILTER_MODE_BLACKLIST)) ?
               SK_FILTER_ALLOW : SK_FILTER_DROP;
    }

    /* this filter type is not enabled in the configuration,
     * so we allow this event.
     */
    return SK_FILTER_ALLOW;
}

static _inline struct pid *
sysk__task_pid(struct task_struct * task)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
    return _(task->thread_pid);
#else
    return _(task->pids[PIDTYPE_PID].pid);
#endif
}

static _inline struct pid_namespace *
sysk__ns_of_pid(struct pid * pid)
{
    struct pid_namespace * ns = NULL;

    if (pid) {
        ns = _(pid->numbers[_(pid->level)].ns);
    }

    return ns;
}

static _inline struct pid_namespace *
sysk__task_active_pid_ns(struct task_struct * tsk)
{
    return sysk__ns_of_pid(sysk__task_pid(tsk));
}

static _inline pid_t
sysk__pid_nr_ns(struct pid           * pid,
                struct pid_namespace * ns)
{
    pid_t         nr = 0;
    unsigned int  ns_level;
    struct upid * upid;

    ns_level = _(ns->level);
    if (pid && ns_level <= _(pid->level)) {
        upid = &pid->numbers[ns_level];

        if (_(upid->ns) == ns) {
            nr = _(upid->nr);
        }
    }

    return nr;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
static _inline struct pid **
task_pid_ptr(struct task_struct * task, enum pid_type type)
{
    return (type == PIDTYPE_PID) ?  &task->thread_pid : &_(task->signal)->pids[type];
}

#endif


/* the pid as seen by the specified namespace */
static _inline pid_t
sysk__task_pid_nr_ns(struct task_struct   * task,
                     enum pid_type          type,
                     struct pid_namespace * ns)
{
    pid_t nr = 0;

    if (!ns) {
        ns = sysk__task_active_pid_ns(task);
    }

    if (type != PIDTYPE_PID) {
        if (type == __PIDTYPE_TGID) {
            type = PIDTYPE_PID;
        }

        task = _(task->group_leader);
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
    nr = sysk__pid_nr_ns(_(*task_pid_ptr(task, type)), ns);
#else
    nr = sysk__pid_nr_ns(_(task->pids[type].pid), ns);
#endif

    return nr;
}

/* virtual pid id (as seen from current) */
static _inline pid_t
sysk__task_pid_vnr(struct task_struct * task)
{
    return sysk__task_pid_nr_ns(task, PIDTYPE_PID, NULL);
}

/* the thread leader pid virtual id (the id seen from the pid namespace of
 * current
 */
static _inline pid_t
sysk__task_tgid_vnr(struct task_struct * task)
{
    return sysk__task_pid_nr_ns(task, __PIDTYPE_TGID, NULL);
}

static _inline pid_t
sysk__task_session_vnr(struct task_struct * task)
{
    return sysk__task_pid_nr_ns(task, PIDTYPE_SID, NULL);
}

static _inline pid_t
sysk__task_session_nr_ns(struct task_struct * task, struct pid_namespace * ns)
{
    return sysk__task_pid_nr_ns(task, PIDTYPE_SID, ns);
}

static _inline struct nsproxy *
sysk__task_nsproxy(struct task_struct * task)
{
    __u32            offset = sysk__get_nsproxy_offset();
    struct nsproxy * nsp;

    memset(&nsp, 0, sizeof(nsp));

    if (bpf_probe_read(&nsp, sizeof(nsp), ((char *)task) + offset) == -EFAULT) {
        return NULL;
    }

    return nsp;
}

static _inline struct ns_common *
sysk__get_pid_ns_common(struct pid_namespace * pid, struct ns_common * out)
{
    __u32 offset = sysk__get_pid_ns_common_offset();

    memset(out, 0, sizeof(*out));
    if (bpf_probe_read(out, sizeof(*out), ((char *)pid) + offset) == -EFAULT) {
        return NULL;
    }

    return out;
}

static _inline void
sysk__event_fill_namespaces(struct sk_event * out, struct task_struct * task)
{
    struct nsproxy          * nsproxy = sysk__task_nsproxy(task);
    struct uts_namespace    * uts_ns  = _(nsproxy->uts_ns);
    struct mnt_namespace    * mnt_ns  = _(nsproxy->mnt_ns);
    struct ipc_namespace    * ipc_ns  = _(nsproxy->ipc_ns);
    struct cgroup_namespace * cgr_ns  = _(nsproxy->cgroup_ns);
    struct pid_namespace    * pid_ns  = _(nsproxy->pid_ns_for_children);
    struct ns_common        * ns;
    struct ns_common          pid_ns_common;

    ns          = &uts_ns->ns;
    out->uts_ns = _(ns->inum);

    ns          = &mnt_ns->ns;
    out->mnt_ns = _(ns->inum);

    ns          = &ipc_ns->ns;
    out->ipc_ns = _(ns->inum);

    ns          = &cgr_ns->ns;
    out->cgr_ns = _(ns->inum);

    if (sysk__get_pid_ns_common(pid_ns, &pid_ns_common)) {
        out->pid_ns = pid_ns_common.inum;
    }
}

static _inline __u32
sysk__task_pid_namespace(struct task_struct * task)
{
    struct nsproxy       * nsproxy = sysk__task_nsproxy(task);
    struct pid_namespace * pid_ns  = _(nsproxy->pid_ns_for_children);
    struct ns_common       ns;

    if (sysk__get_pid_ns_common(pid_ns, &ns)) {
        return ns.inum;
    }

    return -1;
}

static _inline __u32
sysk__task_mnt_namespace(struct task_struct * task)
{
    struct nsproxy       * nsproxy = sysk__task_nsproxy(task);
    struct mnt_namespace * mnt_ns  = _(nsproxy->mnt_ns);
    struct ns_common     * ns;

    ns = &mnt_ns->ns;

    return _(ns->inum);
}

static _inline void
sysk__event_fill_init(struct sk_event * ev, __u32 nr, struct task_struct * task)
{
    memset(ev, 0, BASE_EVENT_SZ);

    sysk__event_fill_namespaces(ev, task);

    ev->syscall    = nr;
    ev->pid_tid    = bpf_get_current_pid_tgid();
    ev->uid_gid    = bpf_get_current_uid_gid();
    ev->session_id = sysk__task_session_vnr(task);
    ev->ns_pid     = sysk__task_tgid_vnr(task);
    ev->context_sw = _(task->nvcsw) + _(task->nivcsw);

    bpf_get_current_comm(ev->comm, sizeof(ev->comm));
}

static _inline long
sysk__syscall_get_nr(struct __args * args)
{
    return args->on_enter.id;
}

static _inline __u8
sysk__run_filter(struct __args * ctx)
{
    __u32                syscall_nr;
    __u32                tid;
    __u32                pidns;
    struct task_struct * task;
    int                  i;

    tid        = bpf_get_current_pid_tgid() >> 32;
    syscall_nr = sysk__syscall_get_nr(ctx);
    task       = (struct task_struct *)bpf_get_current_task();
    pidns      = sysk__task_pid_namespace(task);

    if (sysk__is_filter_enabled(SK_FILTER_MODE_GLOBAL_WHITELIST | SK_FILTER_TYPE_SYSCALL)) {
        if (sysk__eval_filter(SK_FILTER_MODE_GLOBAL_WHITELIST | SK_FILTER_TYPE_SYSCALL, 0, syscall_nr)) {
            /*D_("dropping key=%u\n", syscall_nr); */
            return SK_FILTER_DROP;
        }
    } else {
        struct {
            sk_ftype_t t;
            __u32      ns;
            __u32      key;
        } evaluator[6] = {
            { SK_FILTER_MODE_BLACKLIST | SK_FILTER_TYPE_SYSCALL, pidns, syscall_nr },
            { SK_FILTER_MODE_WHITELIST | SK_FILTER_TYPE_SYSCALL, pidns, syscall_nr },
            { SK_FILTER_MODE_BLACKLIST | SK_FILTER_TYPE_PID,     0,     tid        },
            { SK_FILTER_MODE_WHITELIST | SK_FILTER_TYPE_PID,     0,     tid        },
            { SK_FILTER_MODE_BLACKLIST | SK_FILTER_TYPE_PIDNS,   0,     pidns      },
            { SK_FILTER_MODE_WHITELIST | SK_FILTER_TYPE_PIDNS,   0,     pidns      },
        };

#pragma unroll
        for (i = 0; i < 6; i++) {
            if (sysk__eval_filter(evaluator[i].t, evaluator[i].ns, evaluator[i].key)) {
                /*D_("dropping type=%u, ns=%u, key=%u\n", evaluator[i].t, evaluator[i].ns, evaluator[i].key); */
                return SK_FILTER_DROP;
            }
        }
    }



    return SK_FILTER_ALLOW;
}     /* sysk__run_filter */

#define METRICS_STATE_ENTER 0x01
#define METRICS_STATE_EXIT  0x02

static _inline struct sk_metrics_val *
sysk__lookup_metrics(struct sk_metrics_key * key)
{
    return (struct sk_metrics_val *)bpf_map_lookup_elem(&sk_metrics, key);
}

static _inline void
sysk__update_metrics(const __u32 pid_ns, const __u32 mnt_ns, const __u32 nr, const __s32 err)
{
    struct sk_metrics_key   key         = { 0 };
    struct sk_metrics_val * val;
    struct sk_metrics_val   new_val     = { 0 };
    const __u64             ktime       = bpf_ktime_get_ns();
    __u64                   enter_ktime = 0;/*ktime; */

    key.pid_ns  = pid_ns;
    key.mnt_ns  = mnt_ns;
    key.syscall = nr;

    if (err && err < 255) {
        /* since we assume err == errno, anything that is outside the normal
         * errno range should not be treated as an error.
         */
        /* since we are collecting the timeSpent metric, and we bae
         * that off of the enter_ktime which is set by the entry
         * handler, which has no way to determine an error, so it sets
         * the ktime key with the error field set to 0.
         *
         * So fetch that ktime here.
         */
        if ((val = sysk__lookup_metrics(&key))) {
            enter_ktime = val->_enter_ktime;
        } else {
            enter_ktime = ktime;
        }

        key.error = err;
    }

    if ((val = sysk__lookup_metrics(&key))) {
        if (!err) {
            enter_ktime = val->_enter_ktime;
        }

        memcpy(&new_val, val, sizeof(new_val));
        new_val.time += ktime - enter_ktime;
    } else {
        new_val.first_seen = ktime;
        new_val.time       = 0;
    }

    new_val.count    += 1;
    new_val.last_seen = ktime;


    bpf_map_update_elem(&sk_metrics, &key, &new_val, BPF_ANY);
} /* sysk__update_metrics */

static _inline void
sysk__update_metrics_ktime(const __u32 pid_ns, const __u32 mnt_ns, const __u32 nr)
{
    struct sk_metrics_key   key = {
        .pid_ns  = pid_ns,
        .mnt_ns  = mnt_ns,
        .syscall = nr,
        .error   = 0
    };
    struct sk_metrics_val * val;
    struct sk_metrics_val   new_val = { 0 };
    __u64                   ktime   = bpf_ktime_get_ns();

    if ((val = sysk__lookup_metrics(&key))) {
        memcpy(&new_val, val, sizeof(new_val));
    } else {
        new_val.first_seen = ktime;
    }

    new_val._enter_ktime = ktime;

    bpf_map_update_elem(&sk_metrics, &key, &new_val, BPF_ANY);
}

static _inline void
sysk__fill_metrics(struct __args * ctx, __u8 state)
{
    if (ctx) {
        struct task_struct * task   = (struct task_struct *)bpf_get_current_task();
        __u32                pid_ns = sysk__task_pid_namespace(task);
        __u32                mnt_ns = sysk__task_mnt_namespace(task);
        __u32                nr     = sysk__syscall_get_nr(ctx);

        if (nr == 0xFFFFFFFF) {
            return;
        }

        switch (state) {
            case METRICS_STATE_ENTER:
                /* upon syscall entry, we don't update stats quite yet,
                 * we wait for the EXIT state so we can calculate total
                 * time spent in each call.
                 */
                sysk__update_metrics_ktime(pid_ns, mnt_ns, nr);
                break;
            case METRICS_STATE_EXIT:
            {
                __s32 err = (int)ctx->on_exit.ret < 0 ? -(int)ctx->on_exit.ret : 0;

                sysk__update_metrics(pid_ns, mnt_ns, nr, err);
            }
            break;
        }
    }
}

#define FARGS_FUNC(TYPE) static _inline __u32             \
    sysk__fill_args_ ## TYPE(struct on_enter_args * args, \
            struct on_exit_args * eargs,                  \
            struct sk_event * event)

#define FARGS_INIT(TYPE)           \
    struct __args_ ## TYPE * TYPE; \
                                   \
    if (!args || !event) {         \
        return 2;                  \
    }                              \
                                   \
    event->ret = eargs->ret;       \
                                   \
    TYPE       = (struct __args_ ## TYPE *)args



/**
 * use this to return from syscall-specific argument fillers
 * when the return value is the negated value of the errno
 * which will be sent to userspace.
 */
#define FARGS_COMMON_LTZERO_ERROR (__u32)((int)eargs->ret < 0) ? -(int)eargs->ret : 0

/**
 * use this to return an error condition when a syscalls return
 * value is either NULL or not NULL.
 */
#define FARGS_COMMON_NULL_ERROR   ((const char *)eargs->ret == NULL) ? (__u32) - 1 : 0


/**
 * @brief function that just checks for error conditions in an anonymous
 *        syscall. It should be noted that we will eventually get around
 *        to filling these structures in, but time will tell.
 *
 * @param eargs
 *
 * @return
 */
static _inline __u32
sysk__fill_default_nzeroret_args(struct on_exit_args * eargs)
{
    return FARGS_COMMON_LTZERO_ERROR;
}

/**
 * @see sysk__fill_default_nzeroret_args
 *
 * @param eargs
 *
 * @return
 */
static _inline __u32
sysk__fill_default_nullret_args(struct on_exit_args * eargs)
{
    return FARGS_COMMON_NULL_ERROR;
}

FARGS_FUNC(kill)
{
    FARGS_INIT(kill);

    memcpy(event->_args.a0, &kill->pid, sizeof(kill->pid));
    memcpy(event->_args.a1, &kill->sig, sizeof(kill->sig));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(setuid)
{
    FARGS_INIT(setuid);

    memcpy(event->_args.a0, &setuid->uid, sizeof(setuid->uid));

    return FARGS_COMMON_LTZERO_ERROR;
}

#if 0
/*
 * struct msghdr
 * {
 *  void *msg_name;     // Address to send to/receive from.
 *  socklen_t msg_namelen;  // Length of address data.
 *
 *  struct iovec *msg_iov;  // Vector of data to send/receive into.
 *  size_t msg_iovlen;      // Number of elements in the vector.
 *
 *  void *msg_control;      // Ancillary data (eg BSD filedesc passing).
 *  size_t msg_controllen;  // Ancillary data buffer length.
 *  int msg_flags;      // Flags on received message.
 * };
 */

struct sk_iovec {
    __u16 rlen;
    __u16 trunc;
    __u8  buf[EVENT_ARGSZ - sizeof(__u32)];
} __attribute__((packed));
#endif

FARGS_FUNC(recvmsg)
{
    FARGS_INIT(recvmsg);

    memcpy(event->_args.a0, &recvmsg->fd, sizeof(recvmsg->fd));
    bpf_probe_read(event->_args.a1, sizeof(event->_args.a1), (void *)recvmsg->msg);
    memcpy(event->_args.a2, &recvmsg->flags, sizeof(recvmsg->flags));

#if 0
    if (recvmsg->msg != NULL) {
        struct user_msghdr * hdr = _(recvmsg->msg);

        if (hdr != NULL) {
            size_t            iovlen = _(hdr->msg_iovlen);
            struct iovec    * iov    = _(hdr->msg_iov);
            struct sk_iovec * vec    = (struct sk_iovec *)event->_args.a3;

            memset(event->_args.a3, 0, sizeof(event->_args.a3));
            memset(vec, 0, sizeof(struct sk_iovec));

            vec->rlen = 0;
            switch (iovlen) {
                case 2:
                case 1:
                {
                    size_t len        = _(iov[0].iov_len);
                    size_t bytes_left = sizeof(vec->buf) - vec->rlen;
                    if (len >= bytes_left) {
                        bpf_probe_read(vec->buf, bytes_left - vec->rlen, (void *)&iov[0].iov_base);
                        vec->rlen += bytes_left;
                        vec->trunc = 1;
                    } else {
                        bpf_probe_read(vec->buf, len, (void *)&iov[0].iov_base);
                    }
                }
                break;
            }


            if (iov != NULL) {
                size_t l = _(iov->iov_len);

                D_("%ld %ld\n", l, iovlen);
            }
        }
    }

#endif


    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(sendto)
{
    FARGS_INIT(sendto);

    memcpy(event->_args.a0, &sendto->fd, sizeof(sendto->fd));
    bpf_probe_read(event->_args.a1, sizeof(event->_args.a1), (void *)sendto->ubuf);
    memcpy(event->_args.a2, &sendto->size, sizeof(sendto->size));
    memcpy(event->_args.a3, &sendto->flags, sizeof(sendto->flags));
    bpf_probe_read(event->_args.a4, sizeof(event->_args.a4), (void *)sendto->addr);

    return FARGS_COMMON_LTZERO_ERROR;
}


FARGS_FUNC(recvfrom)
{
    FARGS_INIT(recvfrom);

    memcpy(event->_args.a0, &recvfrom->fd, sizeof(recvfrom->fd));
    bpf_probe_read(event->_args.a1, sizeof(event->_args.a1), (void *)recvfrom->ubuf);
    memcpy(event->_args.a2, &recvfrom->size, sizeof(recvfrom->size));
    memcpy(event->_args.a3, &recvfrom->flags, sizeof(recvfrom->flags));
    bpf_probe_read(event->_args.a4, sizeof(event->_args.a4), (void *)recvfrom->addr);

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(mount)
{
    FARGS_INIT(mount);

    bpf_probe_read(event->_args.a0, sizeof(event->_args.a0), (void *)mount->dev_name);
    bpf_probe_read(event->_args.a1, sizeof(event->_args.a1), (void *)mount->dir_name);
    bpf_probe_read(event->_args.a2, sizeof(event->_args.a2), (void *)mount->type);
    memcpy(event->_args.a3, &mount->flags, sizeof(mount->flags));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(umount2)
{
    FARGS_INIT(umount2);

    bpf_probe_read(event->_args.a0, sizeof(event->_args.a0), (void *)umount2->name);
    memcpy(event->_args.a1, &umount2->flags, sizeof(umount2->flags));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(access)
{
    FARGS_INIT(access);

    bpf_probe_read(event->_args.a0, sizeof(event->_args.a0), (void *)access->filename);
    memcpy(event->_args.a1, &access->mode, sizeof(access->mode));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(prlimit64)
{
    FARGS_INIT(prlimit64);

    memcpy(event->_args.a0, &prlimit64->pid, sizeof(prlimit64->pid));
    memcpy(event->_args.a1, &prlimit64->resource, sizeof(prlimit64->resource));

    bpf_probe_read(event->_args.a2, sizeof(event->_args.a2), (void *)prlimit64->new_rlim);
    bpf_probe_read(event->_args.a3, sizeof(event->_args.a3), (void *)prlimit64->old_rlim);

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(setns)
{
    FARGS_INIT(setns);

    memcpy(event->_args.a0, &setns->fd, sizeof(setns->fd));
    memcpy(event->_args.a1, &setns->nstype, sizeof(setns->nstype));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(bind)
{
    FARGS_INIT(bind);

    memcpy(event->_args.a0, &bind->fd, sizeof(bind->fd));
    bpf_probe_read(event->_args.a1, sizeof(event->_args.a1), bind->umyaddr);
    memcpy(event->_args.a2, &bind->addrlen, sizeof(bind->addrlen));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(socket)
{
    FARGS_INIT(socket);

    memcpy(event->_args.a0, &socket->family, sizeof(socket->family));
    memcpy(event->_args.a1, &socket->type, sizeof(socket->type));
    memcpy(event->_args.a2, &socket->protocol, sizeof(socket->protocol));

    return FARGS_COMMON_LTZERO_ERROR;
}


FARGS_FUNC(openat)
{
    FARGS_INIT(openat);

    memcpy(event->_args.a0, &openat->dfd, sizeof(openat->dfd));
    bpf_probe_read(event->_args.a1, sizeof(event->_args.a1), openat->filename);
    memcpy(event->_args.a2, &openat->flags, sizeof(openat->flags));


    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(open)
{
    FARGS_INIT(open);

    bpf_probe_read(event->_args.a0, sizeof(event->_args.a0), open->filename);
    memcpy(event->_args.a1, &open->flags, sizeof(open->flags));
    memcpy(event->_args.a2, &open->mode, sizeof(open->mode));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(connect)
{
    FARGS_INIT(connect);
    struct sockaddr * a = (void *)_(connect->uservaddr);

    memcpy(event->_args.a0, &connect->fd, sizeof(connect->fd));
    bpf_probe_read(event->_args.a1, sizeof(event->_args.a1), a);
    memcpy(event->_args.a2, &connect->addrlen, sizeof(connect->addrlen));

    return FARGS_COMMON_LTZERO_ERROR;
}


FARGS_FUNC(execve)
{
    FARGS_INIT(execve);

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(unlink)
{
    FARGS_INIT(unlink);

    bpf_probe_read(event->_args.a0, sizeof(event->_args.a0), unlink->pathname);

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(unlinkat)
{
    FARGS_INIT(unlinkat);

    memcpy(event->_args.a0, &unlinkat->dfd, sizeof(unlinkat->dfd));
    bpf_probe_read(event->_args.a1, sizeof(event->_args.a1), unlinkat->pathname);
    memcpy(event->_args.a2, &unlinkat->offset, sizeof(unlinkat->offset));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(epoll_wait)
{
    FARGS_INIT(epoll_wait);

    memcpy(event->_args.a0, &epoll_wait->epfd, sizeof(epoll_wait->epfd));
    memcpy(event->_args.a2, &epoll_wait->maxevents, sizeof(epoll_wait->maxevents));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(faccessat)
{
    FARGS_INIT(faccessat);

    memcpy(event->_args.a0, &faccessat->dfd, sizeof(faccessat->dfd));
    memcpy(event->_args.a2, &faccessat->mode, sizeof(faccessat->mode));
    memcpy(event->_args.a2, &faccessat->mode, sizeof(faccessat->mode));
    bpf_probe_read(event->_args.a1, sizeof(event->_args.a1), faccessat->filename);

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(statx)
{
    FARGS_INIT(statx);

    memcpy(event->_args.a0, &statx->dfd, sizeof(statx->dfd));
    bpf_probe_read(event->_args.a1, sizeof(event->_args.a1), statx->filename);
    memcpy(event->_args.a2, &statx->flags, sizeof(statx->flags));
    memcpy(event->_args.a3, &statx->mask, sizeof(statx->mask));
    bpf_probe_read(event->_args.a4, sizeof(event->_args.a4), statx->buffer);

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(syslog)
{
    FARGS_INIT(syslog);

    memcpy(event->_args.a0, &syslog->type, sizeof(syslog->type));
    bpf_probe_read(event->_args.a1, sizeof(event->_args.a1), syslog->buf);
    memcpy(event->_args.a2, &syslog->len, sizeof(syslog->len));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(fcntl)
{
    FARGS_INIT(fcntl);

    memcpy(event->_args.a0, &fcntl->fd, sizeof(fcntl->fd));
    memcpy(event->_args.a1, &fcntl->cmd, sizeof(fcntl->cmd));
    memcpy(event->_args.a2, &fcntl->arg, sizeof(fcntl->arg));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(fdatasync)
{
    FARGS_INIT(fdatasync);

    memcpy(event->_args.a0, &fdatasync->fd, sizeof(fdatasync->fd));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(fstatfs)
{
    FARGS_INIT(fstatfs);

    memcpy(event->_args.a0, &fstatfs->fd, sizeof(fstatfs->fd));
    bpf_probe_read(event->_args.a1, sizeof(event->_args.a1), fstatfs->buf);

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(fstat)
{
    FARGS_INIT(fstat);

    memcpy(event->_args.a0, &fstat->fd, sizeof(fstat->fd));
    bpf_probe_read(event->_args.a1, sizeof(event->_args.a1), fstat->statbuf);

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(stat)
{
    FARGS_INIT(stat);

    bpf_probe_read(event->_args.a0, sizeof(event->_args.a0), (void *)stat->filename);
    bpf_probe_read(event->_args.a1, sizeof(event->_args.a1), (void *)stat->statbuf);

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(statfs)
{
    FARGS_INIT(statfs);

    bpf_probe_read(event->_args.a0, sizeof(event->_args.a0), (void *)statfs->pathname);
    bpf_probe_read(event->_args.a1, sizeof(event->_args.a1), statfs->buf);

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(acct)
{
    FARGS_INIT(acct);

    bpf_probe_read(event->_args.a0, sizeof(event->_args.a0), (void *)acct->pathname);

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(alarm)
{
    FARGS_INIT(alarm);

    memcpy(event->_args.a0, &alarm->seconds, sizeof(alarm->seconds));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(brk)
{
    FARGS_INIT(brk);

    memcpy(event->_args.a0, &brk->addr, sizeof(brk->addr));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(fsync)
{
    FARGS_INIT(fsync);

    memcpy(event->_args.a0, &fsync->fd, sizeof(fsync->fd));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(ftruncate)
{
    FARGS_INIT(ftruncate);

    memcpy(event->_args.a0, &ftruncate->fd, sizeof(ftruncate->fd));
    memcpy(event->_args.a1, &ftruncate->length, sizeof(ftruncate->length));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(getcwd)
{
    FARGS_INIT(getcwd);

    bpf_probe_read(event->_args.a0, sizeof(event->_args.a0), getcwd->buf);
    memcpy(event->_args.a1, &getcwd->size, sizeof(getcwd->size));

    return FARGS_COMMON_NULL_ERROR;
}

FARGS_FUNC(getdents)
{
    FARGS_INIT(getdents);

    memcpy(event->_args.a0, &getdents->fd, sizeof(getdents->fd));
    memcpy(event->_args.a2, &getdents->count, sizeof(getdents->count));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(inotify_add_watch)
{
    FARGS_INIT(inotify_add_watch);

    memcpy(event->_args.a0, &inotify_add_watch->fd, sizeof(inotify_add_watch->fd));
    bpf_probe_read(event->_args.a1, sizeof(event->_args.a1), inotify_add_watch->pathname);
    memcpy(event->_args.a2, &inotify_add_watch->mask, sizeof(inotify_add_watch->mask));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(listen)
{
    FARGS_INIT(listen);

    memcpy(event->_args.a0, &listen->fd, sizeof(listen->fd));
    memcpy(event->_args.a1, &listen->backlog, sizeof(listen->backlog));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(lookup_dcookie)
{
    FARGS_INIT(lookup_dcookie);

    memcpy(event->_args.a0, &lookup_dcookie->cookie64, sizeof(lookup_dcookie->cookie64));
    memcpy(event->_args.a2, &lookup_dcookie->len, sizeof(lookup_dcookie->len));
    bpf_probe_read(event->_args.a1, sizeof(event->_args.a1), lookup_dcookie->buf);

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(lseek)
{
    FARGS_INIT(lseek);

    memcpy(event->_args.a0, &lseek->fd, sizeof(lseek->fd));
    memcpy(event->_args.a1, &lseek->offset, sizeof(lseek->offset));
    memcpy(event->_args.a2, &lseek->whence, sizeof(lseek->whence));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(madvise)
{
    FARGS_INIT(madvise);

    memcpy(event->_args.a0, &madvise->start, sizeof(madvise->start));
    memcpy(event->_args.a1, &madvise->len_in, sizeof(madvise->len_in));
    memcpy(event->_args.a2, &madvise->behavior, sizeof(madvise->behavior));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(membarrier)
{
    FARGS_INIT(membarrier);

    memcpy(event->_args.a0, &membarrier->cmd, sizeof(membarrier->cmd));
    memcpy(event->_args.a1, &membarrier->flags, sizeof(membarrier->flags));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(mkdir)
{
    FARGS_INIT(mkdir);

    bpf_probe_read(event->_args.a0, sizeof(event->_args.a0), mkdir->pathname);
    memcpy(event->_args.a1, &mkdir->mode, sizeof(mkdir->mode));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(mkdirat)
{
    FARGS_INIT(mkdirat);

    memcpy(event->_args.a0, &mkdirat->dfd, sizeof(mkdirat->dfd));
    bpf_probe_read(event->_args.a1, sizeof(event->_args.a1), mkdirat->pathname);
    memcpy(event->_args.a2, &mkdirat->mode, sizeof(mkdirat->mode));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(mknod)
{
    FARGS_INIT(mknod);

    bpf_probe_read(event->_args.a0, sizeof(event->_args.a0), mknod->filename);
    memcpy(event->_args.a1, &mknod->mode, sizeof(mknod->mode));
    memcpy(event->_args.a2, &mknod->dev, sizeof(mknod->dev));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(mlock)
{
    FARGS_INIT(mlock);

    memcpy(event->_args.a0, &mlock->start, sizeof(mlock->start));
    memcpy(event->_args.a1, &mlock->len, sizeof(mlock->len));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(pivot_root)
{
    FARGS_INIT(pivot_root);

    bpf_probe_read(event->_args.a0, sizeof(event->_args.a0), pivot_root->new_root);
    bpf_probe_read(event->_args.a1, sizeof(event->_args.a1), pivot_root->put_old);

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(poll)
{
    FARGS_INIT(poll);

    memcpy(event->_args.a1, &poll->nfds, sizeof(poll->nfds));
    memcpy(event->_args.a2, &poll->timeout_msecs, sizeof(poll->timeout_msecs));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(prctl)
{
    FARGS_INIT(prctl);

    memcpy(event->_args.a0, &prctl->option, sizeof(prctl->option));
    memcpy(event->_args.a1, &prctl->arg2, sizeof(prctl->arg2));
    memcpy(event->_args.a2, &prctl->arg3, sizeof(prctl->arg3));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(ptrace)
{
    FARGS_INIT(ptrace);

    memcpy(event->_args.a0, &ptrace->request, sizeof(ptrace->request));
    memcpy(event->_args.a1, &ptrace->pid, sizeof(ptrace->pid));
    memcpy(event->_args.a2, &ptrace->addr, sizeof(ptrace->addr));
    memcpy(event->_args.a3, &ptrace->data, sizeof(ptrace->data));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(close)
{
    FARGS_INIT(close);

    memcpy(event->_args.a0, &close->fd, sizeof(close->fd));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(rmdir)
{
    FARGS_INIT(rmdir);

    bpf_probe_read(event->_args.a0, sizeof(event->_args.a0), (void *)rmdir->pathname);

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(chdir)
{
    FARGS_INIT(chdir);

    bpf_probe_read(event->_args.a0, sizeof(event->_args.a0), (void *)chdir->filename);

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(fchdir)
{
    FARGS_INIT(fchdir);

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(chroot)
{
    FARGS_INIT(chroot);

    bpf_probe_read(event->_args.a0, sizeof(event->_args.a0), (void *)chroot->filename);

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(link)
{
    FARGS_INIT(link);

    bpf_probe_read(event->_args.a0, sizeof(event->_args.a0), (void *)link->oldname);
    bpf_probe_read(event->_args.a1, sizeof(event->_args.a1), (void *)link->newname);

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(linkat)
{
    FARGS_INIT(linkat);

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(symlink)
{
    FARGS_INIT(symlink);

    bpf_probe_read(event->_args.a0, sizeof(event->_args.a0), (void *)symlink->oldname);
    bpf_probe_read(event->_args.a1, sizeof(event->_args.a1), (void *)symlink->newname);

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(symlinkat)
{
    FARGS_INIT(symlinkat);

    return FARGS_COMMON_LTZERO_ERROR;
}


FARGS_FUNC(readlink)
{
    FARGS_INIT(readlink);

    bpf_probe_read(event->_args.a0, sizeof(event->_args.a0), (void *)readlink->path);
    bpf_probe_read(event->_args.a1, sizeof(event->_args.a1), (void *)readlink->buf);
    memcpy(event->_args.a2, &readlink->bufsiz, sizeof(readlink->bufsiz));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(readlinkat)
{
    FARGS_INIT(readlinkat);

    memcpy(event->_args.a0, &readlinkat->dfd, sizeof(readlinkat->dfd));
    bpf_probe_read(event->_args.a1, sizeof(event->_args.a0), (void *)readlinkat->pathname);
    bpf_probe_read(event->_args.a2, sizeof(event->_args.a1), (void *)readlinkat->buf);
    memcpy(event->_args.a3, &readlinkat->bufsiz, sizeof(readlinkat->bufsiz));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(getpeername)
{
    FARGS_INIT(getpeername);

    memcpy(event->_args.a0, &getpeername->fd, sizeof(getpeername->fd));
    bpf_probe_read(event->_args.a1, sizeof(event->_args.a1), getpeername->usockaddr);
    memcpy(event->_args.a2, &getpeername->usockaddr_len, sizeof(getpeername->usockaddr_len));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(getsockname)
{
    FARGS_INIT(getsockname);

    memcpy(event->_args.a0, &getsockname->fd, sizeof(getsockname->fd));
    bpf_probe_read(event->_args.a1, sizeof(event->_args.a1), getsockname->usockaddr);
    memcpy(event->_args.a2, &getsockname->usockaddr_len, sizeof(getsockname->usockaddr_len));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(accept)
{
    FARGS_INIT(accept);

    memcpy(event->_args.a0, &accept->fd, sizeof(accept->fd));
    bpf_probe_read(event->_args.a1, sizeof(event->_args.a1), accept->saddr);
    memcpy(event->_args.a2, &accept->saddr_len, sizeof(accept->saddr_len));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(accept4)
{
    FARGS_INIT(accept);

    memcpy(event->_args.a0, &accept->fd, sizeof(accept->fd));
    bpf_probe_read(event->_args.a1, sizeof(event->_args.a1), accept->saddr);
    memcpy(event->_args.a2, &accept->saddr_len, sizeof(accept->saddr_len));
    memcpy(event->_args.a3, &accept->flags, sizeof(accept->flags));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(mprotect)
{
    FARGS_INIT(mprotect);

    memcpy(event->_args.a0, &mprotect->start, sizeof(mprotect->start));
    memcpy(event->_args.a1, &mprotect->len, sizeof(mprotect->len));
    memcpy(event->_args.a2, &mprotect->prot, sizeof(mprotect->prot));
    bpf_probe_read(event->_args.a3, sizeof(event->_args.a3), (void *)mprotect->start);

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(setsockopt)
{
    FARGS_INIT(setsockopt);

    memcpy(event->_args.a0, &setsockopt->fd, sizeof(setsockopt->fd));
    memcpy(event->_args.a1, &setsockopt->level, sizeof(setsockopt->level));
    memcpy(event->_args.a2, &setsockopt->optname, sizeof(setsockopt->optname));
    bpf_probe_read(event->_args.a3, sizeof(event->_args.a3), setsockopt->optval);
    memcpy(event->_args.a4, &setsockopt->optlen, sizeof(setsockopt->optlen));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(getsockopt)
{
    FARGS_INIT(getsockopt);

    memcpy(event->_args.a0, &getsockopt->fd, sizeof(getsockopt->fd));
    memcpy(event->_args.a1, &getsockopt->level, sizeof(getsockopt->level));
    memcpy(event->_args.a2, &getsockopt->optname, sizeof(getsockopt->optname));
    bpf_probe_read(event->_args.a3, sizeof(__u64), getsockopt->optval);
    bpf_probe_read(event->_args.a4, sizeof(__u64 *), getsockopt->optlen);

    return FARGS_COMMON_LTZERO_ERROR;
}


FARGS_FUNC(creat)
{
    FARGS_INIT(creat);

    bpf_probe_read(event->_args.a0, sizeof(event->_args.a0), (void *)creat->pathname);
    memcpy(event->_args.a1, &creat->mode, sizeof(creat->mode));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(init_module)
{
    FARGS_INIT(init_module);

    bpf_probe_read(event->_args.a0, sizeof(event->_args.a0), init_module->umod);
    memcpy(event->_args.a1, &init_module->len, sizeof(init_module->len));
    bpf_probe_read(event->_args.a2, sizeof(event->_args.a2), init_module->uargs);

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(seccomp)
{
    FARGS_INIT(seccomp);

    memcpy(event->_args.a0, &seccomp->op, sizeof(seccomp->op));
    memcpy(event->_args.a1, &seccomp->flags, sizeof(seccomp->flags));
    bpf_probe_read(event->_args.a2, sizeof(event->_args.a2), (void *)seccomp->uargs);

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(sethostname)
{
    FARGS_INIT(sethostname);

    bpf_probe_read(event->_args.a0, sizeof(event->_args.a0), (void *)sethostname->name);
    memcpy(event->_args.a1, &sethostname->len, sizeof(sethostname->len));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(clone)
{
    FARGS_INIT(clone);

    memcpy(event->_args.a0, &clone->flags, sizeof(clone->flags));
    memcpy(event->_args.a1, &clone->newsp, sizeof(clone->newsp));
    bpf_probe_read(event->_args.a2, sizeof(event->_args.a2), (void *)clone->parent_tidptr);
    bpf_probe_read(event->_args.a3, sizeof(event->_args.a3), (void *)clone->child_tidptr);
    memcpy(event->_args.a4, &clone->tls, sizeof(clone->tls));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(read)
{
    FARGS_INIT(read);

    memcpy(event->_args.a0, &read->fd, sizeof(read->fd));
    bpf_probe_read(event->_args.a1, sizeof(event->_args.a1), (void *)read->buf);
    memcpy(event->_args.a2, &read->count, sizeof(read->count));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(write)
{
    FARGS_INIT(write);

    memcpy(event->_args.a0, &write->fd, sizeof(write->fd));
    bpf_probe_read(event->_args.a1, sizeof(event->_args.a1), (void *)write->buf);
    memcpy(event->_args.a2, &write->count, sizeof(write->count));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(ioctl)
{
    FARGS_INIT(ioctl);

    memcpy(event->_args.a0, &ioctl->fd, sizeof(ioctl->fd));
    memcpy(event->_args.a1, &ioctl->cmd, sizeof(ioctl->cmd));
    bpf_probe_read(event->_args.a2, sizeof(event->_args.a2), (void *)ioctl->arg);

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(rename)
{
    FARGS_INIT(rename);

    bpf_probe_read(event->_args.a0, sizeof(event->_args.a0), (void *)rename->oldname);
    bpf_probe_read(event->_args.a1, sizeof(event->_args.a1), (void *)rename->newname);

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(timerfd_settime)
{
    FARGS_INIT(timerfd_settime);

    memcpy(event->_args.a0, &timerfd_settime->ufd, sizeof(timerfd_settime->ufd));
    memcpy(event->_args.a1, &timerfd_settime->flags, sizeof(timerfd_settime->flags));
    bpf_probe_read(event->_args.a2, sizeof(event->_args.a2), (void *)timerfd_settime->utmr);
    bpf_probe_read(event->_args.a3, sizeof(event->_args.a3), (void *)timerfd_settime->otmr);

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(timerfd_create)
{
    FARGS_INIT(timerfd_create);

    memcpy(event->_args.a0, &timerfd_create->clockid, sizeof(timerfd_create->clockid));
    memcpy(event->_args.a1, &timerfd_create->flags, sizeof(timerfd_create->flags));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(mincore)
{
    FARGS_INIT(mincore);

    memcpy(event->_args.a0, &mincore->start, sizeof(mincore->start));
    memcpy(event->_args.a1, &mincore->len, sizeof(mincore->len));
    bpf_probe_read(event->_args.a2, sizeof(event->_args.a2), (void *)mincore->vec);

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(nanosleep)
{
    FARGS_INIT(nanosleep);

    bpf_probe_read(event->_args.a0, sizeof(event->_args.a0), (void *)nanosleep->rqtp);
    bpf_probe_read(event->_args.a1, sizeof(event->_args.a1), (void *)nanosleep->rmtp);

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(rt_sigaction)
{
    FARGS_INIT(rt_sigaction);

    memcpy(event->_args.a0, &rt_sigaction->sig, sizeof(rt_sigaction->sig));
    bpf_probe_read(event->_args.a1, sizeof(event->_args.a1), (void *)rt_sigaction->act);
    bpf_probe_read(event->_args.a2, sizeof(event->_args.a2), (void *)rt_sigaction->oact);
    memcpy(event->_args.a3, &rt_sigaction->sigsetsize, sizeof(rt_sigaction->sigsetsize));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(futex)
{
    FARGS_INIT(futex);

    memcpy(event->_args.a0, &futex->uaddr, sizeof(futex->uaddr));
    memcpy(event->_args.a1, &futex->op, sizeof(futex->op));
    memcpy(event->_args.a2, &futex->val, sizeof(futex->val));
    memcpy(event->_args.a3, &futex->utime, sizeof(futex->utime));
    memcpy(event->_args.a4, &futex->uaddr2, sizeof(futex->uaddr2));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(select)
{
    FARGS_INIT(select);

    memcpy(event->_args.a0, &select->n, sizeof(select->n));
    memcpy(event->_args.a1, &select->inp, sizeof(select->inp));
    memcpy(event->_args.a2, &select->outp, sizeof(select->outp));
    memcpy(event->_args.a3, &select->exp, sizeof(select->exp));
    memcpy(event->_args.a4, &select->tvp, sizeof(select->tvp));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(umask)
{
    FARGS_INIT(umask);

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(exit)
{
    FARGS_INIT(exit);

    memcpy(event->_args.a0, &exit->error_code, sizeof(exit->error_code));

    return FARGS_COMMON_LTZERO_ERROR;
}


SEC("tracepoint/raw_syscalls/sys_enter") int
sysk__enter(struct __args * ctx)
{
    __u64               pid_tid    = bpf_get_current_pid_tgid();
    __u32               syscall_nr = sysk__syscall_get_nr(ctx);
    struct sk_event_key ev_key;

#ifndef SC__NO_METRICS
    sysk__fill_metrics(ctx, METRICS_STATE_ENTER);
#endif

#ifdef SC__METRICS_ONLY
    /* compiled with metrics-only, so yeah... just return */
    return 0;
#endif

    /* since we have a static tracepoint specifically for execve, we can safely
     * ignore this.
     */
    if (syscall_nr == __NR_execve) {
        return 0;
    }

    if (sysk__run_filter(ctx) == SK_FILTER_DROP) {
        return 0;
    }

    memset(&ev_key, 0, sizeof(struct sk_event_key));
    memcpy(&ev_key.on_enter, &ctx->on_enter, sizeof(struct on_enter_args));

    ev_key.uid_gid        = bpf_get_current_uid_gid();
    ev_key.entr_timestamp = bpf_ktime_get_ns();

    bpf_map_update_elem(&sk_state_map, &pid_tid, &ev_key, BPF_ANY);

    return 0;
}     /* sysk__enter */

SEC("tracepoint/raw_syscalls/sys_exit") int
sysk__exit(struct __args * ctx)
{
    __u64                 pid_tid;
    __u32                 cpu;
    struct sk_event_key * ev_key;
    struct sk_event     * event;
    struct task_struct  * task;

#ifndef SC__NO_METRICS
    sysk__fill_metrics(ctx, METRICS_STATE_EXIT);
#endif

#ifdef SC__METRICS_ONLY
    /* metrics only, return... */
    return 0;
#endif

    pid_tid = bpf_get_current_pid_tgid();

    if ((ev_key = bpf_map_lookup_elem(&sk_state_map, &pid_tid)) == NULL) {
        return 0;
    }

    cpu = bpf_get_smp_processor_id();

    if ((event = bpf_map_lookup_elem(&sk_event_scratch, &cpu)) == NULL) {
        bpf_map_delete_elem(&sk_state_map, &pid_tid);
        return 0;
    }

    /* make sure we're looking at the same syscall..... */
    if (ctx->on_exit.id != ev_key->on_enter.id) {
        bpf_map_delete_elem(&sk_state_map, &pid_tid);
        return 0;
    }

    task = (struct task_struct *)bpf_get_current_task();

    sysk__event_fill_init(event, ev_key->on_enter.id, task);
    sysk__event_fill_namespaces(event, task);

    event->uid_gid   = ev_key->uid_gid;
    event->entr_usec = ev_key->entr_timestamp;
    event->exit_usec = bpf_ktime_get_ns();

    #define FARGS_CALL(TYPE)                                                       \
        case __NR_ ## TYPE:                                                        \
            event->errno =                                                         \
                sysk__fill_args_ ## TYPE(&ev_key->on_enter, &ctx->on_exit, event); \
            break

    switch (event->syscall) {
        FARGS_CALL(kill);
        FARGS_CALL(acct);
        FARGS_CALL(alarm);
        FARGS_CALL(brk);
        FARGS_CALL(close);
        FARGS_CALL(access);
        FARGS_CALL(openat);
        FARGS_CALL(open);
        FARGS_CALL(connect);
        FARGS_CALL(execve);
        FARGS_CALL(unlink);
        FARGS_CALL(unlinkat);
        FARGS_CALL(epoll_wait);
        FARGS_CALL(faccessat);
        FARGS_CALL(statx);
        FARGS_CALL(syslog);
        FARGS_CALL(fcntl);
        FARGS_CALL(fdatasync);
        FARGS_CALL(fstatfs);
        FARGS_CALL(fstat);
        FARGS_CALL(statfs);
        FARGS_CALL(fsync);
        FARGS_CALL(ftruncate);
        FARGS_CALL(getcwd);
        FARGS_CALL(getdents);
        FARGS_CALL(inotify_add_watch);
        FARGS_CALL(listen);
        FARGS_CALL(lookup_dcookie);
        FARGS_CALL(lseek);
        FARGS_CALL(madvise);
        FARGS_CALL(membarrier);
        FARGS_CALL(mkdir);
        FARGS_CALL(mkdirat);
        FARGS_CALL(mknod);
        FARGS_CALL(mlock);
        FARGS_CALL(pivot_root);
        FARGS_CALL(poll);
        FARGS_CALL(prctl);
        FARGS_CALL(rmdir);
        FARGS_CALL(chdir);
        FARGS_CALL(fchdir);
        FARGS_CALL(chroot);
        FARGS_CALL(link);
        FARGS_CALL(linkat);
        FARGS_CALL(symlink);
        FARGS_CALL(symlinkat);
        FARGS_CALL(bind);
        FARGS_CALL(socket);
        FARGS_CALL(setns);
        FARGS_CALL(prlimit64);
        FARGS_CALL(mount);
        FARGS_CALL(umount2);
        FARGS_CALL(recvmsg);
        FARGS_CALL(setuid);
        FARGS_CALL(recvfrom);
        FARGS_CALL(sendto);
        FARGS_CALL(ptrace);
        FARGS_CALL(readlink);
        FARGS_CALL(readlinkat);
        FARGS_CALL(getpeername);
        FARGS_CALL(getsockname);
        FARGS_CALL(accept);
        FARGS_CALL(accept4);
        FARGS_CALL(mprotect);
        FARGS_CALL(setsockopt);
        FARGS_CALL(getsockopt);
        FARGS_CALL(creat);
        FARGS_CALL(init_module);
        FARGS_CALL(seccomp);
        FARGS_CALL(stat);
        FARGS_CALL(sethostname);
        FARGS_CALL(clone);
        FARGS_CALL(read);
        FARGS_CALL(write);
        FARGS_CALL(ioctl);
        FARGS_CALL(rename);
        FARGS_CALL(timerfd_settime);
        FARGS_CALL(timerfd_create);
        FARGS_CALL(mincore);
        FARGS_CALL(nanosleep);
        FARGS_CALL(rt_sigaction);
        FARGS_CALL(futex);
        FARGS_CALL(select);
        FARGS_CALL(exit);
        default:
            event->_args.a0[0] = '\0';
            event->_args.a1[0] = '\0';
            event->_args.a2[0] = '\0';
            event->_args.a3[0] = '\0';
            event->_args.a4[0] = '\0';
            sysk__fill_default_nzeroret_args(&ctx->on_exit);
            break;
    }     /* switch */

    bpf_perf_event_output(ctx, &sk_perf_output,
            BPF_F_CURRENT_CPU, event, sizeof(struct sk_event));
    bpf_map_delete_elem(&sk_state_map, &pid_tid);

    return 0;
}     /* sysk__exit */

SEC("tracepoint/syscalls/sys_enter_execve") int
sysk__syscalls_execve(struct __args * ctx)
{
#ifdef SC__METRICS_ONLY
    /* handled by sys_enter tracepoint */
    return 0;
#endif
    struct sk_event    * event = NULL;
    __u32                cpu   = bpf_get_smp_processor_id();
    __u64                tid   = bpf_get_current_pid_tgid() >> 32;
    struct task_struct * task  = (struct task_struct *)bpf_get_current_task();

    if (sysk__run_filter(ctx) == SK_FILTER_DROP) {
        return 0;
    }

    if ((event = bpf_map_lookup_elem(&sk_event_scratch, &cpu)) == NULL) {
        return 0;
    }

    sysk__event_fill_init(event, __NR_execve, task);
    sysk__event_fill_namespaces(event, task);

    event->entr_usec = event->exit_usec = bpf_ktime_get_ns();

    bpf_probe_read(event->_args.a0, sizeof(event->_args.a0), (void *)ctx->execve.filename);
    bpf_probe_read(event->_args.a1, sizeof(event->_args.a1), _(ctx->execve.argv[1]));
    bpf_probe_read(event->_args.a2, sizeof(event->_args.a2), _(ctx->execve.argv[2]));
    bpf_probe_read(event->_args.a3, sizeof(event->_args.a3), _(ctx->execve.argv[3]));
    bpf_probe_read(event->_args.a4, sizeof(event->_args.a4), _(ctx->execve.argv[4]));

    bpf_perf_event_output(ctx, &sk_perf_output,
            BPF_F_CURRENT_CPU, event, sizeof(struct sk_event));

    return 0;
}     /* sysk__syscalls_execve */

__u8 _license[] SEC("license") = "GPL";
__u32 _version  SEC("version") = 0xFFFFFFFE;
