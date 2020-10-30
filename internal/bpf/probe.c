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


#if defined(SC__DEBUG)
#define D_(fmt, ...)                                          \
    ({                                                        \
        char _fmt[] = fmt;                                    \
        bpf_trace_printk(_fmt, sizeof(_fmt), ## __VA_ARGS__); \
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


FARGS_STRUCT_DEF(kill) {
    __s32 nr;
    __u64 pid;
    __u64 sig;
};

FARGS_STRUCT_DEF(acct) {
    __s32        nr;
    const char * pathname;
};

FARGS_STRUCT_DEF(alarm) {
    __s32 nr;
    __u64 seconds;
};

FARGS_STRUCT_DEF(brk) {
    __s32 nr;
    __u64 addr;
};

FARGS_STRUCT_DEF(statfs) {
    __s32           nr;
    const char    * pathname;
    struct statfs * buf;
};

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

FARGS_STRUCT_DEF(mount) {
    __u32  nr;
    char * dev_name;
    char * dir_name;
    char * type;
    __u64  flags;
    void * data;
};

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

FARGS_STRUCT_DEF(setns) {
    __s32 nr;
    __u64 fd;
    __u64 nstype;
};

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

FARGS_STRUCT_DEF(prlimit64) {
    __u32                   nr;
    __u64                   pid;
    __u64                   resource;
    const struct rlimit64 * new_rlim;
    struct rlimit64       * old_rlim;
};

FARGS_STRUCT_DEF(recvmsg) {
    __u32                nr;
    __s64                fd;
    struct user_msghdr * msg;
    __u64                flags;
};


FARGS_STRUCT_DEF(sendto) {
    __u32             nr;
    __u64             fd;
    void            * ubuf;
    __u64             size;
    __u64             flags;
    struct sockaddr * addr;
    __u64             addr_len;
};

FARGS_STRUCT_DEF(recvfrom) {
    __u32             nr;
    __u64             fd;
    void            * ubuf;
    __u64             size;
    __u64             flags;
    struct sockaddr * addr;
    __u64           * addr_len;
};

FARGS_STRUCT_DEF(setuid) {
    __u32 nr;
    __u64 uid;
};

FARGS_STRUCT_DEF(setreuid) {
    __u32 nr;
    __u64 ruid;
    __u64 euid;
};

FARGS_STRUCT_DEF(close) {
    __u32 nr;
    __u64 fd;
};

FARGS_STRUCT_DEF(rmdir) {
    __u32        nr;
    const char * pathname;
};

FARGS_STRUCT_DEF(ptrace) {
    __u32 nr;
    __u64 request;
    __u64 pid;
    __u64 addr;
    __u64 data;
};

FARGS_STRUCT_DEF(chdir) {
    __u32        nr;
    const char * filename;
};


FARGS_STRUCT_DEF(chroot) {
    __u32        nr;
    const char * filename;
};

FARGS_STRUCT_DEF(link) {
    __u32        nr;
    const char * oldname;
    const char * newname;
};

FARGS_STRUCT_DEF(readlink) {
    __u32        nr;
    const char * path;
    char       * buf;
    __u64        bufsiz;
};

FARGS_STRUCT_DEF(readlinkat) {
    __u32        nr;
    __u64        dfd;
    const char * pathname;
    char       * buf;
    __u64        bufsiz;
};

FARGS_STRUCT_DEF(symlink) {
    __u32        nr;
    const char * oldname;
    const char * newname;
};

FARGS_STRUCT_DEF(getpeername) {
    __u32             nr;
    __u64             fd;
    struct sockaddr * usockaddr;
    __u64           * usockaddr_len;
};

FARGS_STRUCT_DEF(getsockname) {
    __u32             nr;
    __u64             fd;
    struct sockaddr * usockaddr;
    __u64             usockaddr_len;
};

FARGS_STRUCT_DEF(accept) {
    __u32             nr;
    __u64             fd;
    struct sockaddr * saddr;
    __u64           * saddr_len;
    __u64             flags;
};

FARGS_STRUCT_DEF(mprotect) {
    __u32 nr;
    __u64 start;
    __u64 len;
    __u64 prot;
};

FARGS_STRUCT_DEF(setsockopt) {
    __u32  nr;
    __u64  fd;
    __u64  level;
    __u64  optname;
    char * optval;
    __u64  optlen;
};

FARGS_STRUCT_DEF(getsockopt) {
    __u32   nr;
    __u64   fd;
    __u64   level;
    __u64   optname;
    char  * optval;
    __u64 * optlen;
};

FARGS_STRUCT_DEF(creat) {
    __u32        nr;
    const char * pathname;
    __u64        mode;
};

FARGS_STRUCT_DEF(init_module) {
    __u32   nr;
    void  * umod;
    __u64   len;
    __u64 * uargs;
};

FARGS_STRUCT_DEF(seccomp) {
    __u32        nr;
    __u64        op;
    __u64        flags;
    const char * uargs;
};

FARGS_STRUCT_DEF(sethostname) {
    __u32  nr;
    char * name;
    __u64  len;
};

FARGS_STRUCT_DEF(clone) {
    __u32   nr;
    __u64   flags;
    __u64   newsp;
    __u64 * parent_tidptr;
    __u64 * child_tidptr;
    __u64   tls;
};

FARGS_STRUCT_DEF(read) {
    __u32  nr;
    __u64  fd;
    char * buf;
    __u64  count;
};

FARGS_STRUCT_DEF(ioctl) {
    __u32 nr;
    __u64 fd;
    __u64 cmd;
    __u64 arg;
};

FARGS_STRUCT_DEF(rename) {
    __u32        nr;
    const char * oldname;
    const char * newname;
};

FARGS_STRUCT_DEF(timerfd_settime) {
    __u32                     nr;
    __u64                     flags;
    __u64                     ufd;
    const struct itimerspec * utmr;
    struct itimerspec       * otmr;
};

FARGS_STRUCT_DEF(timerfd_create) {
    __u32 nr;
    __u64 clockid;
    __u64 flags;
};

FARGS_STRUCT_DEF(mincore)
{
    __u32           nr;
    __u64           start;
    __u64           len;
    unsigned char * vec;
};

FARGS_STRUCT_DEF(ftruncate)
{
    __u32 nr;
    __u64 fd;
    __u64 length;
};

FARGS_STRUCT_DEF(nanosleep)
{
    __u32             nr;
    struct timespec * rqtp;
    struct timespec * rmtp;
};

FARGS_STRUCT_DEF(rt_sigaction) {
    __u32              nr;
    __u64              sig;
    struct sigaction * act;
    struct sigaction * oact;
    __u64              sigsetsize;
};

FARGS_STRUCT_DEF(write)
{
    __u32        nr;
    __u64        fd;
    const char * buf;
    __u64        count;
};

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

#define EVENT_ARG0(ev) (ev)->_args.a0
#define EVENT_ARG1(ev) (ev)->_args.a1
#define EVENT_ARG2(ev) (ev)->_args.a2
#define EVENT_ARG3(ev) (ev)->_args.a3
#define EVENT_ARG4(ev) (ev)->_args.a4

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
    #define SK_OSCFG_NSPROXY 1
    #define SK_OSCFG_PIDNS   2
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
sysk__update_metrics(const __u32 pid_ns, const __u32 nr, const __s32 err)
{
    struct sk_metrics_key   key         = { 0 };
    struct sk_metrics_val * val;
    struct sk_metrics_val   new_val     = { 0 };
    const __u64             ktime       = bpf_ktime_get_ns();
    __u64                   enter_ktime = 0;/*ktime; */

    key.pid_ns  = pid_ns;
    key.syscall = nr;

    if (err && err < 255) {
        /* we assume err == errno, anything that is outside the normal
         * errno range should not be treated as an error.
         *
         * Since we are collecting the timeSpent metric, we base
         * that off of the enter_ktime which is set by the entry
         * handler - a function which has no way to determine an error, if one has occured.
         * So this sets the ktime key with the error field set to 0.
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
sysk__update_metrics_ktime(const __u32 pid_ns, const __u32 nr)
{
    struct sk_metrics_key   key = {
        .pid_ns  = pid_ns,
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
                sysk__update_metrics_ktime(pid_ns, nr);
                break;
            case METRICS_STATE_EXIT:
            {
                __s32 err = (int)ctx->on_exit.ret < 0 ? -(int)ctx->on_exit.ret : 0;

                sysk__update_metrics(pid_ns, nr, err);
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

    memcpy(EVENT_ARG0(event), &kill->pid, sizeof(kill->pid));
    memcpy(EVENT_ARG1(event), &kill->sig, sizeof(kill->sig));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(setuid)
{
    FARGS_INIT(setuid);

    memcpy(EVENT_ARG0(event), &setuid->uid, sizeof(setuid->uid));

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

    memcpy(EVENT_ARG0(event), &recvmsg->fd, sizeof(recvmsg->fd));
    bpf_probe_read(EVENT_ARG1(event), sizeof(EVENT_ARG1(event)), (void *)recvmsg->msg);
    memcpy(EVENT_ARG2(event), &recvmsg->flags, sizeof(recvmsg->flags));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(sendto)
{
    FARGS_INIT(sendto);

    memcpy(EVENT_ARG0(event), &sendto->fd, sizeof(sendto->fd));
    bpf_probe_read(EVENT_ARG1(event), sizeof(EVENT_ARG1(event)), (void *)sendto->ubuf);
    memcpy(EVENT_ARG2(event), &sendto->size, sizeof(sendto->size));
    memcpy(EVENT_ARG3(event), &sendto->flags, sizeof(sendto->flags));
    bpf_probe_read(EVENT_ARG4(event), sizeof(EVENT_ARG4(event)), (void *)sendto->addr);

    return FARGS_COMMON_LTZERO_ERROR;
}


FARGS_FUNC(recvfrom)
{
    FARGS_INIT(recvfrom);

    memcpy(EVENT_ARG0(event), &recvfrom->fd, sizeof(recvfrom->fd));
    bpf_probe_read(EVENT_ARG1(event), sizeof(EVENT_ARG1(event)), (void *)recvfrom->ubuf);
    memcpy(EVENT_ARG2(event), &recvfrom->size, sizeof(recvfrom->size));
    memcpy(EVENT_ARG3(event), &recvfrom->flags, sizeof(recvfrom->flags));
    bpf_probe_read(EVENT_ARG4(event), sizeof(EVENT_ARG4(event)), (void *)recvfrom->addr);

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(mount)
{
    FARGS_INIT(mount);

    bpf_probe_read(EVENT_ARG0(event), sizeof(EVENT_ARG0(event)), (void *)mount->dev_name);
    bpf_probe_read(EVENT_ARG1(event), sizeof(EVENT_ARG1(event)), (void *)mount->dir_name);
    bpf_probe_read(EVENT_ARG2(event), sizeof(EVENT_ARG2(event)), (void *)mount->type);
    memcpy(EVENT_ARG3(event), &mount->flags, sizeof(mount->flags));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(umount2)
{
    FARGS_INIT(umount2);

    bpf_probe_read(EVENT_ARG0(event), sizeof(EVENT_ARG0(event)), (void *)umount2->name);
    memcpy(EVENT_ARG1(event), &umount2->flags, sizeof(umount2->flags));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(access)
{
    FARGS_INIT(access);

    bpf_probe_read(EVENT_ARG0(event), sizeof(EVENT_ARG0(event)), (void *)access->filename);
    memcpy(EVENT_ARG1(event), &access->mode, sizeof(access->mode));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(prlimit64)
{
    FARGS_INIT(prlimit64);

    memcpy(EVENT_ARG0(event), &prlimit64->pid, sizeof(prlimit64->pid));
    memcpy(EVENT_ARG1(event), &prlimit64->resource, sizeof(prlimit64->resource));
    bpf_probe_read(EVENT_ARG2(event), sizeof(EVENT_ARG2(event)), (void *)prlimit64->new_rlim);
    bpf_probe_read(EVENT_ARG3(event), sizeof(EVENT_ARG3(event)), (void *)prlimit64->old_rlim);

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(setns)
{
    FARGS_INIT(setns);

    memcpy(EVENT_ARG0(event), &setns->fd, sizeof(setns->fd));
    memcpy(EVENT_ARG1(event), &setns->nstype, sizeof(setns->nstype));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(bind)
{
    FARGS_INIT(bind);

    memcpy(EVENT_ARG0(event), &bind->fd, sizeof(bind->fd));
    bpf_probe_read(EVENT_ARG1(event), sizeof(EVENT_ARG1(event)), bind->umyaddr);
    memcpy(EVENT_ARG2(event), &bind->addrlen, sizeof(bind->addrlen));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(socket)
{
    FARGS_INIT(socket);

    memcpy(EVENT_ARG0(event), &socket->family, sizeof(socket->family));
    memcpy(EVENT_ARG1(event), &socket->type, sizeof(socket->type));
    memcpy(EVENT_ARG2(event), &socket->protocol, sizeof(socket->protocol));

    return FARGS_COMMON_LTZERO_ERROR;
}


FARGS_FUNC(openat)
{
    FARGS_INIT(openat);

    memcpy(EVENT_ARG0(event), &openat->dfd, sizeof(openat->dfd));
    bpf_probe_read(EVENT_ARG1(event), sizeof(EVENT_ARG1(event)), openat->filename);
    memcpy(EVENT_ARG2(event), &openat->flags, sizeof(openat->flags));


    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(open)
{
    FARGS_INIT(open);

    bpf_probe_read(EVENT_ARG0(event), sizeof(EVENT_ARG0(event)), open->filename);
    memcpy(EVENT_ARG1(event), &open->flags, sizeof(open->flags));
    memcpy(EVENT_ARG2(event), &open->mode, sizeof(open->mode));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(connect)
{
    FARGS_INIT(connect);
    struct sockaddr * a = (void *)_(connect->uservaddr);

    memcpy(EVENT_ARG0(event), &connect->fd, sizeof(connect->fd));
    bpf_probe_read(EVENT_ARG1(event), sizeof(EVENT_ARG1(event)), a);
    memcpy(EVENT_ARG2(event), &connect->addrlen, sizeof(connect->addrlen));

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

    bpf_probe_read(EVENT_ARG0(event), sizeof(EVENT_ARG0(event)), unlink->pathname);

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(unlinkat)
{
    FARGS_INIT(unlinkat);

    memcpy(EVENT_ARG0(event), &unlinkat->dfd, sizeof(unlinkat->dfd));
    bpf_probe_read(EVENT_ARG1(event), sizeof(EVENT_ARG1(event)), unlinkat->pathname);
    memcpy(EVENT_ARG2(event), &unlinkat->offset, sizeof(unlinkat->offset));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(epoll_wait)
{
    FARGS_INIT(epoll_wait);

    memcpy(EVENT_ARG0(event), &epoll_wait->epfd, sizeof(epoll_wait->epfd));
    memcpy(EVENT_ARG2(event), &epoll_wait->maxevents, sizeof(epoll_wait->maxevents));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(faccessat)
{
    FARGS_INIT(faccessat);

    memcpy(EVENT_ARG0(event), &faccessat->dfd, sizeof(faccessat->dfd));
    bpf_probe_read(EVENT_ARG1(event), sizeof(EVENT_ARG1(event)), faccessat->filename);
    memcpy(EVENT_ARG2(event), &faccessat->mode, sizeof(faccessat->mode));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(statx)
{
    FARGS_INIT(statx);

    memcpy(EVENT_ARG0(event), &statx->dfd, sizeof(statx->dfd));
    bpf_probe_read(EVENT_ARG1(event), sizeof(EVENT_ARG1(event)), statx->filename);
    memcpy(EVENT_ARG2(event), &statx->flags, sizeof(statx->flags));
    memcpy(EVENT_ARG3(event), &statx->mask, sizeof(statx->mask));
    bpf_probe_read(EVENT_ARG4(event), sizeof(EVENT_ARG4(event)), statx->buffer);

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(syslog)
{
    FARGS_INIT(syslog);

    memcpy(EVENT_ARG0(event), &syslog->type, sizeof(syslog->type));
    bpf_probe_read(EVENT_ARG1(event), sizeof(EVENT_ARG1(event)), syslog->buf);
    memcpy(EVENT_ARG2(event), &syslog->len, sizeof(syslog->len));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(fcntl)
{
    FARGS_INIT(fcntl);

    memcpy(EVENT_ARG0(event), &fcntl->fd, sizeof(fcntl->fd));
    memcpy(EVENT_ARG1(event), &fcntl->cmd, sizeof(fcntl->cmd));
    memcpy(EVENT_ARG2(event), &fcntl->arg, sizeof(fcntl->arg));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(fdatasync)
{
    FARGS_INIT(fdatasync);

    memcpy(EVENT_ARG0(event), &fdatasync->fd, sizeof(fdatasync->fd));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(fstatfs)
{
    FARGS_INIT(fstatfs);

    memcpy(EVENT_ARG0(event), &fstatfs->fd, sizeof(fstatfs->fd));
    bpf_probe_read(EVENT_ARG1(event), sizeof(EVENT_ARG1(event)), fstatfs->buf);

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(fstat)
{
    FARGS_INIT(fstat);

    memcpy(EVENT_ARG0(event), &fstat->fd, sizeof(fstat->fd));
    bpf_probe_read(EVENT_ARG1(event), sizeof(EVENT_ARG1(event)), fstat->statbuf);

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(stat)
{
    FARGS_INIT(stat);

    bpf_probe_read(EVENT_ARG0(event), sizeof(EVENT_ARG0(event)), (void *)stat->filename);
    bpf_probe_read(EVENT_ARG1(event), sizeof(EVENT_ARG1(event)), (void *)stat->statbuf);

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(statfs)
{
    FARGS_INIT(statfs);

    bpf_probe_read(EVENT_ARG0(event), sizeof(EVENT_ARG0(event)), (void *)statfs->pathname);
    bpf_probe_read(EVENT_ARG1(event), sizeof(EVENT_ARG1(event)), statfs->buf);

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(acct)
{
    FARGS_INIT(acct);

    bpf_probe_read(EVENT_ARG0(event), sizeof(EVENT_ARG0(event)), (void *)acct->pathname);

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(alarm)
{
    FARGS_INIT(alarm);

    memcpy(EVENT_ARG0(event), &alarm->seconds, sizeof(alarm->seconds));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(brk)
{
    FARGS_INIT(brk);

    memcpy(EVENT_ARG0(event), &brk->addr, sizeof(brk->addr));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(fsync)
{
    FARGS_INIT(fsync);

    memcpy(EVENT_ARG0(event), &fsync->fd, sizeof(fsync->fd));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(ftruncate)
{
    FARGS_INIT(ftruncate);

    memcpy(EVENT_ARG0(event), &ftruncate->fd, sizeof(ftruncate->fd));
    memcpy(EVENT_ARG1(event), &ftruncate->length, sizeof(ftruncate->length));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(getcwd)
{
    FARGS_INIT(getcwd);

    bpf_probe_read(EVENT_ARG0(event), sizeof(EVENT_ARG0(event)), getcwd->buf);
    memcpy(EVENT_ARG1(event), &getcwd->size, sizeof(getcwd->size));

    return FARGS_COMMON_NULL_ERROR;
}

FARGS_FUNC(getdents)
{
    FARGS_INIT(getdents);

    memcpy(EVENT_ARG0(event), &getdents->fd, sizeof(getdents->fd));
    memcpy(EVENT_ARG2(event), &getdents->count, sizeof(getdents->count));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(inotify_add_watch)
{
    FARGS_INIT(inotify_add_watch);

    memcpy(EVENT_ARG0(event), &inotify_add_watch->fd, sizeof(inotify_add_watch->fd));
    bpf_probe_read(EVENT_ARG1(event), sizeof(EVENT_ARG1(event)), inotify_add_watch->pathname);
    memcpy(EVENT_ARG2(event), &inotify_add_watch->mask, sizeof(inotify_add_watch->mask));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(listen)
{
    FARGS_INIT(listen);

    memcpy(EVENT_ARG0(event), &listen->fd, sizeof(listen->fd));
    memcpy(EVENT_ARG1(event), &listen->backlog, sizeof(listen->backlog));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(lookup_dcookie)
{
    FARGS_INIT(lookup_dcookie);

    memcpy(EVENT_ARG0(event), &lookup_dcookie->cookie64, sizeof(lookup_dcookie->cookie64));
    memcpy(EVENT_ARG2(event), &lookup_dcookie->len, sizeof(lookup_dcookie->len));
    bpf_probe_read(EVENT_ARG1(event), sizeof(EVENT_ARG1(event)), lookup_dcookie->buf);

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(lseek)
{
    FARGS_INIT(lseek);

    memcpy(EVENT_ARG0(event), &lseek->fd, sizeof(lseek->fd));
    memcpy(EVENT_ARG1(event), &lseek->offset, sizeof(lseek->offset));
    memcpy(EVENT_ARG2(event), &lseek->whence, sizeof(lseek->whence));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(madvise)
{
    FARGS_INIT(madvise);

    memcpy(EVENT_ARG0(event), &madvise->start, sizeof(madvise->start));
    memcpy(EVENT_ARG1(event), &madvise->len_in, sizeof(madvise->len_in));
    memcpy(EVENT_ARG2(event), &madvise->behavior, sizeof(madvise->behavior));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(membarrier)
{
    FARGS_INIT(membarrier);

    memcpy(EVENT_ARG0(event), &membarrier->cmd, sizeof(membarrier->cmd));
    memcpy(EVENT_ARG1(event), &membarrier->flags, sizeof(membarrier->flags));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(mkdir)
{
    FARGS_INIT(mkdir);

    bpf_probe_read(EVENT_ARG0(event), sizeof(EVENT_ARG0(event)), mkdir->pathname);
    memcpy(EVENT_ARG1(event), &mkdir->mode, sizeof(mkdir->mode));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(mkdirat)
{
    FARGS_INIT(mkdirat);

    memcpy(EVENT_ARG0(event), &mkdirat->dfd, sizeof(mkdirat->dfd));
    bpf_probe_read(EVENT_ARG1(event), sizeof(EVENT_ARG1(event)), mkdirat->pathname);
    memcpy(EVENT_ARG2(event), &mkdirat->mode, sizeof(mkdirat->mode));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(mknod)
{
    FARGS_INIT(mknod);

    bpf_probe_read(EVENT_ARG0(event), sizeof(EVENT_ARG0(event)), mknod->filename);
    memcpy(EVENT_ARG1(event), &mknod->mode, sizeof(mknod->mode));
    memcpy(EVENT_ARG2(event), &mknod->dev, sizeof(mknod->dev));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(mlock)
{
    FARGS_INIT(mlock);

    memcpy(EVENT_ARG0(event), &mlock->start, sizeof(mlock->start));
    memcpy(EVENT_ARG1(event), &mlock->len, sizeof(mlock->len));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(pivot_root)
{
    FARGS_INIT(pivot_root);

    bpf_probe_read(EVENT_ARG0(event), sizeof(EVENT_ARG0(event)), pivot_root->new_root);
    bpf_probe_read(EVENT_ARG1(event), sizeof(EVENT_ARG1(event)), pivot_root->put_old);

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(poll)
{
    FARGS_INIT(poll);

    memcpy(EVENT_ARG1(event), &poll->nfds, sizeof(poll->nfds));
    memcpy(EVENT_ARG2(event), &poll->timeout_msecs, sizeof(poll->timeout_msecs));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(prctl)
{
    FARGS_INIT(prctl);

    memcpy(EVENT_ARG0(event), &prctl->option, sizeof(prctl->option));
    memcpy(EVENT_ARG1(event), &prctl->arg2, sizeof(prctl->arg2));
    memcpy(EVENT_ARG2(event), &prctl->arg3, sizeof(prctl->arg3));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(ptrace)
{
    FARGS_INIT(ptrace);

    memcpy(EVENT_ARG0(event), &ptrace->request, sizeof(ptrace->request));
    memcpy(EVENT_ARG1(event), &ptrace->pid, sizeof(ptrace->pid));
    memcpy(EVENT_ARG2(event), &ptrace->addr, sizeof(ptrace->addr));
    memcpy(EVENT_ARG3(event), &ptrace->data, sizeof(ptrace->data));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(close)
{
    FARGS_INIT(close);

    memcpy(EVENT_ARG0(event), &close->fd, sizeof(close->fd));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(rmdir)
{
    FARGS_INIT(rmdir);

    bpf_probe_read(EVENT_ARG0(event), sizeof(EVENT_ARG0(event)), (void *)rmdir->pathname);

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(chdir)
{
    FARGS_INIT(chdir);

    bpf_probe_read(EVENT_ARG0(event), sizeof(EVENT_ARG0(event)), (void *)chdir->filename);

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

    bpf_probe_read(EVENT_ARG0(event), sizeof(EVENT_ARG0(event)), (void *)chroot->filename);

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(link)
{
    FARGS_INIT(link);

    bpf_probe_read(EVENT_ARG0(event), sizeof(EVENT_ARG0(event)), (void *)link->oldname);
    bpf_probe_read(EVENT_ARG1(event), sizeof(EVENT_ARG1(event)), (void *)link->newname);

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

    bpf_probe_read(EVENT_ARG0(event), sizeof(EVENT_ARG0(event)), (void *)symlink->oldname);
    bpf_probe_read(EVENT_ARG1(event), sizeof(EVENT_ARG1(event)), (void *)symlink->newname);

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

    bpf_probe_read(EVENT_ARG0(event), sizeof(EVENT_ARG0(event)), (void *)readlink->path);
    bpf_probe_read(EVENT_ARG1(event), sizeof(EVENT_ARG1(event)), (void *)readlink->buf);
    memcpy(EVENT_ARG2(event), &readlink->bufsiz, sizeof(readlink->bufsiz));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(readlinkat)
{
    FARGS_INIT(readlinkat);

    memcpy(EVENT_ARG0(event), &readlinkat->dfd, sizeof(readlinkat->dfd));
    bpf_probe_read(EVENT_ARG1(event), sizeof(EVENT_ARG0(event)), (void *)readlinkat->pathname);
    bpf_probe_read(EVENT_ARG2(event), sizeof(EVENT_ARG1(event)), (void *)readlinkat->buf);
    memcpy(EVENT_ARG3(event), &readlinkat->bufsiz, sizeof(readlinkat->bufsiz));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(getpeername)
{
    FARGS_INIT(getpeername);

    memcpy(EVENT_ARG0(event), &getpeername->fd, sizeof(getpeername->fd));
    bpf_probe_read(EVENT_ARG1(event), sizeof(EVENT_ARG1(event)), getpeername->usockaddr);
    memcpy(EVENT_ARG2(event), &getpeername->usockaddr_len, sizeof(getpeername->usockaddr_len));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(getsockname)
{
    FARGS_INIT(getsockname);

    memcpy(EVENT_ARG0(event), &getsockname->fd, sizeof(getsockname->fd));
    bpf_probe_read(EVENT_ARG1(event), sizeof(EVENT_ARG1(event)), getsockname->usockaddr);
    memcpy(EVENT_ARG2(event), &getsockname->usockaddr_len, sizeof(getsockname->usockaddr_len));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(accept)
{
    FARGS_INIT(accept);

    memcpy(EVENT_ARG0(event), &accept->fd, sizeof(accept->fd));
    bpf_probe_read(EVENT_ARG1(event), sizeof(EVENT_ARG1(event)), accept->saddr);
    memcpy(EVENT_ARG2(event), &accept->saddr_len, sizeof(accept->saddr_len));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(accept4)
{
    FARGS_INIT(accept);

    memcpy(EVENT_ARG0(event), &accept->fd, sizeof(accept->fd));
    bpf_probe_read(EVENT_ARG1(event), sizeof(EVENT_ARG1(event)), accept->saddr);
    memcpy(EVENT_ARG2(event), &accept->saddr_len, sizeof(accept->saddr_len));
    memcpy(EVENT_ARG3(event), &accept->flags, sizeof(accept->flags));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(mprotect)
{
    FARGS_INIT(mprotect);

    memcpy(EVENT_ARG0(event), &mprotect->start, sizeof(mprotect->start));
    memcpy(EVENT_ARG1(event), &mprotect->len, sizeof(mprotect->len));
    memcpy(EVENT_ARG2(event), &mprotect->prot, sizeof(mprotect->prot));
    bpf_probe_read(EVENT_ARG3(event), sizeof(EVENT_ARG3(event)), (void *)mprotect->start);

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(setsockopt)
{
    FARGS_INIT(setsockopt);

    memcpy(EVENT_ARG0(event), &setsockopt->fd, sizeof(setsockopt->fd));
    memcpy(EVENT_ARG1(event), &setsockopt->level, sizeof(setsockopt->level));
    memcpy(EVENT_ARG2(event), &setsockopt->optname, sizeof(setsockopt->optname));
    bpf_probe_read(EVENT_ARG3(event), sizeof(EVENT_ARG3(event)), setsockopt->optval);
    memcpy(EVENT_ARG4(event), &setsockopt->optlen, sizeof(setsockopt->optlen));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(getsockopt)
{
    FARGS_INIT(getsockopt);

    memcpy(EVENT_ARG0(event), &getsockopt->fd, sizeof(getsockopt->fd));
    memcpy(EVENT_ARG1(event), &getsockopt->level, sizeof(getsockopt->level));
    memcpy(EVENT_ARG2(event), &getsockopt->optname, sizeof(getsockopt->optname));
    bpf_probe_read(EVENT_ARG3(event), sizeof(__u64), getsockopt->optval);
    bpf_probe_read(EVENT_ARG4(event), sizeof(__u64 *), getsockopt->optlen);

    return FARGS_COMMON_LTZERO_ERROR;
}


FARGS_FUNC(creat)
{
    FARGS_INIT(creat);

    bpf_probe_read(EVENT_ARG0(event), sizeof(EVENT_ARG0(event)), (void *)creat->pathname);
    memcpy(EVENT_ARG1(event), &creat->mode, sizeof(creat->mode));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(init_module)
{
    FARGS_INIT(init_module);

    bpf_probe_read(EVENT_ARG0(event), sizeof(EVENT_ARG0(event)), init_module->umod);
    memcpy(EVENT_ARG1(event), &init_module->len, sizeof(init_module->len));
    bpf_probe_read(EVENT_ARG2(event), sizeof(EVENT_ARG2(event)), init_module->uargs);

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(seccomp)
{
    FARGS_INIT(seccomp);

    memcpy(EVENT_ARG0(event), &seccomp->op, sizeof(seccomp->op));
    memcpy(EVENT_ARG1(event), &seccomp->flags, sizeof(seccomp->flags));
    bpf_probe_read(EVENT_ARG2(event), sizeof(EVENT_ARG2(event)), (void *)seccomp->uargs);

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(sethostname)
{
    FARGS_INIT(sethostname);

    bpf_probe_read(EVENT_ARG0(event), sizeof(EVENT_ARG0(event)), (void *)sethostname->name);
    memcpy(EVENT_ARG1(event), &sethostname->len, sizeof(sethostname->len));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(clone)
{
    FARGS_INIT(clone);

    memcpy(EVENT_ARG0(event), &clone->flags, sizeof(clone->flags));
    memcpy(EVENT_ARG1(event), &clone->newsp, sizeof(clone->newsp));
    bpf_probe_read(EVENT_ARG2(event), sizeof(EVENT_ARG2(event)), (void *)clone->parent_tidptr);
    bpf_probe_read(EVENT_ARG3(event), sizeof(EVENT_ARG3(event)), (void *)clone->child_tidptr);
    memcpy(EVENT_ARG4(event), &clone->tls, sizeof(clone->tls));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(read)
{
    FARGS_INIT(read);

    memcpy(EVENT_ARG0(event), &read->fd, sizeof(read->fd));
    bpf_probe_read(EVENT_ARG1(event), sizeof(EVENT_ARG1(event)), (void *)read->buf);
    memcpy(EVENT_ARG2(event), &read->count, sizeof(read->count));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(write)
{
    FARGS_INIT(write);

    memcpy(EVENT_ARG0(event), &write->fd, sizeof(write->fd));
    bpf_probe_read(EVENT_ARG1(event), sizeof(EVENT_ARG1(event)), (void *)write->buf);
    memcpy(EVENT_ARG2(event), &write->count, sizeof(write->count));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(ioctl)
{
    FARGS_INIT(ioctl);

    memcpy(EVENT_ARG0(event), &ioctl->fd, sizeof(ioctl->fd));
    memcpy(EVENT_ARG1(event), &ioctl->cmd, sizeof(ioctl->cmd));
    bpf_probe_read(EVENT_ARG2(event), sizeof(EVENT_ARG2(event)), (void *)ioctl->arg);

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(rename)
{
    FARGS_INIT(rename);

    bpf_probe_read(EVENT_ARG0(event), sizeof(EVENT_ARG0(event)), (void *)rename->oldname);
    bpf_probe_read(EVENT_ARG1(event), sizeof(EVENT_ARG1(event)), (void *)rename->newname);

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(timerfd_settime)
{
    FARGS_INIT(timerfd_settime);

    memcpy(EVENT_ARG0(event), &timerfd_settime->ufd, sizeof(timerfd_settime->ufd));
    memcpy(EVENT_ARG1(event), &timerfd_settime->flags, sizeof(timerfd_settime->flags));
    bpf_probe_read(EVENT_ARG2(event), sizeof(EVENT_ARG2(event)), (void *)timerfd_settime->utmr);
    bpf_probe_read(EVENT_ARG3(event), sizeof(EVENT_ARG3(event)), (void *)timerfd_settime->otmr);

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(timerfd_create)
{
    FARGS_INIT(timerfd_create);

    memcpy(EVENT_ARG0(event), &timerfd_create->clockid, sizeof(timerfd_create->clockid));
    memcpy(EVENT_ARG1(event), &timerfd_create->flags, sizeof(timerfd_create->flags));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(mincore)
{
    FARGS_INIT(mincore);

    memcpy(EVENT_ARG0(event), &mincore->start, sizeof(mincore->start));
    memcpy(EVENT_ARG1(event), &mincore->len, sizeof(mincore->len));
    bpf_probe_read(EVENT_ARG2(event), sizeof(EVENT_ARG2(event)), (void *)mincore->vec);

    return FARGS_COMMON_LTZERO_ERROR;
}


FARGS_FUNC(nanosleep)
{
    FARGS_INIT(nanosleep);

    bpf_probe_read(EVENT_ARG0(event), sizeof(EVENT_ARG0(event)), (void *)nanosleep->rqtp);
    bpf_probe_read(EVENT_ARG1(event), sizeof(EVENT_ARG1(event)), (void *)nanosleep->rmtp);

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(rt_sigaction)
{
    FARGS_INIT(rt_sigaction);

    memcpy(EVENT_ARG0(event), &rt_sigaction->sig, sizeof(rt_sigaction->sig));
    bpf_probe_read(EVENT_ARG1(event), sizeof(EVENT_ARG1(event)), (void *)rt_sigaction->act);
    bpf_probe_read(EVENT_ARG2(event), sizeof(EVENT_ARG2(event)), (void *)rt_sigaction->oact);
    memcpy(EVENT_ARG3(event), &rt_sigaction->sigsetsize, sizeof(rt_sigaction->sigsetsize));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(futex)
{
    FARGS_INIT(futex);

    memcpy(EVENT_ARG0(event), &futex->uaddr, sizeof(futex->uaddr));
    memcpy(EVENT_ARG1(event), &futex->op, sizeof(futex->op));
    memcpy(EVENT_ARG2(event), &futex->val, sizeof(futex->val));
    memcpy(EVENT_ARG3(event), &futex->utime, sizeof(futex->utime));
    memcpy(EVENT_ARG4(event), &futex->uaddr2, sizeof(futex->uaddr2));

    return FARGS_COMMON_LTZERO_ERROR;
}

FARGS_FUNC(select)
{
    FARGS_INIT(select);

    memcpy(EVENT_ARG0(event), &select->n, sizeof(select->n));
    memcpy(EVENT_ARG1(event), &select->inp, sizeof(select->inp));
    memcpy(EVENT_ARG2(event), &select->outp, sizeof(select->outp));
    memcpy(EVENT_ARG3(event), &select->exp, sizeof(select->exp));
    memcpy(EVENT_ARG4(event), &select->tvp, sizeof(select->tvp));

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

    memcpy(EVENT_ARG0(event), &exit->error_code, sizeof(exit->error_code));

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
            EVENT_ARG0(event)[0] = '\0';
            EVENT_ARG1(event)[0] = '\0';
            EVENT_ARG2(event)[0] = '\0';
            EVENT_ARG3(event)[0] = '\0';
            EVENT_ARG4(event)[0] = '\0';
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

    bpf_probe_read(EVENT_ARG0(event), sizeof(EVENT_ARG0(event)), (void *)ctx->execve.filename);
    bpf_probe_read(EVENT_ARG1(event), sizeof(EVENT_ARG1(event)), _(ctx->execve.argv[1]));
    bpf_probe_read(EVENT_ARG2(event), sizeof(EVENT_ARG2(event)), _(ctx->execve.argv[2]));
    bpf_probe_read(EVENT_ARG3(event), sizeof(EVENT_ARG3(event)), _(ctx->execve.argv[3]));
    bpf_probe_read(EVENT_ARG4(event), sizeof(EVENT_ARG4(event)), _(ctx->execve.argv[4]));

    bpf_perf_event_output(ctx, &sk_perf_output,
            BPF_F_CURRENT_CPU, event, sizeof(struct sk_event));

    return 0;
}     /* sysk__syscalls_execve */

__u8 _license[] SEC("license") = "GPL";
__u32 _version  SEC("version") = 0xFFFFFFFE;
