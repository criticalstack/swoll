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

#define bpf_probe_memset(dest, chr, n)   __builtin_memset((dest), (chr), (n))
#define bpf_probe_memcpy(dest, src, n)   __builtin_memcpy((dest), (src), (n))

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0) && LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
#define randomized_struct_fields_start struct {
#define randomized_struct_fields_end \
};
#endif

#ifndef __PIDTYPE_TGID
#define __PIDTYPE_TGID                 PIDTYPE_MAX + 1
#endif

#define _(P)                                      \
    ({                                            \
        typeof(P) _val;                           \
        bpf_probe_memset(&_val, 0, sizeof(_val)); \
        bpf_probe_read(&_val, sizeof(_val), &P);  \
        _val;                                     \
    })


#if defined(SWOLL__DEBUG)
#define D_(fmt, ...)                                          \
    ({                                                        \
        char _fmt[] = fmt;                                    \
        bpf_trace_printk(_fmt, sizeof(_fmt), ## __VA_ARGS__); \
    })
#else
#define D_(fmt, ...)
#endif

#define _(P)                             ({       \
        typeof(P) _val;                           \
        bpf_probe_memset(&_val, 0, sizeof(_val)); \
        bpf_probe_read(&_val, sizeof(_val), &P);  \
        _val;                                     \
    })


#define _inline                        inline __attribute__((always_inline))

struct swoll_event_args_common {
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

#define SWOLL_STRUCT_DEF(TYPE) struct swoll_event_args_ ## TYPE
#define SWOLL_STRUCT(TYPE)     SWOLL_STRUCT_DEF(TYPE) TYPE


SWOLL_STRUCT_DEF(kill) {
    __s32 nr;
    __u64 pid;
    __u64 sig;
};

SWOLL_STRUCT_DEF(acct) {
    __s32        nr;
    const char * pathname;
};

SWOLL_STRUCT_DEF(alarm) {
    __s32 nr;
    __u64 seconds;
};

SWOLL_STRUCT_DEF(brk) {
    __s32 nr;
    __u64 addr;
};

SWOLL_STRUCT_DEF(statfs) {
    __s32           nr;
    const char    * pathname;
    struct statfs * buf;
};

SWOLL_STRUCT_DEF(fstat) {
    __u32         nr;
    __u64         fd;
    struct stat * statbuf;
};


SWOLL_STRUCT_DEF(stat) {
    __u32         nr;
    const char  * filename;
    struct stat * statbuf;
};

SWOLL_STRUCT_DEF(mount) {
    __u32  nr;
    char * dev_name;
    char * dir_name;
    char * type;
    __u64  flags;
    void * data;
};

SWOLL_STRUCT_DEF(umount2) {
    __u32  nr;
    char * name;
    __u64  flags;
};

SWOLL_STRUCT_DEF(openat) {
    __s32   nr;
    __s64   dfd;
    __u64 * filename;
    __u64   flags;
    __u64   mode;
};

SWOLL_STRUCT_DEF(open) {
    __u32   nr;
    __u64 * filename;
    __s64   flags;
    __u64   mode;
};

SWOLL_STRUCT_DEF(connect) {
    __u32  nr;
    __s64  fd;
    void * uservaddr;
    __u64  addrlen;
};


SWOLL_STRUCT_DEF(execve) {
    __u32   nr;
    char  * filename;
    char ** argv;
    char ** envp;
};

SWOLL_STRUCT_DEF(bind) {
    __u32             nr;
    __u64             fd;
    struct sockaddr * umyaddr;
    __u64             addrlen;
};


SWOLL_STRUCT_DEF(sched_process_fork) {
    char  parent_comm[16];
    pid_t parent_pid;
    char  child_comm[16];
    pid_t child_pid;
};

SWOLL_STRUCT_DEF(unlink) {
    __u32  nr;
    char * pathname;
};


SWOLL_STRUCT_DEF(epoll_wait) {
    __u32                nr;
    __u64                epfd;
    struct epoll_event * events;
    __u64                maxevents;
    __u64                timeout;
};


SWOLL_STRUCT_DEF(unlinkat) {
    __u32  nr;
    __u64  dfd;
    char * pathname;
    __u64  offset;
};

SWOLL_STRUCT_DEF(mmap) {
    __u32 nr;
    __u64 addr;
    __u64 len;
    __u64 prot;
    __u64 flags;
    __u64 fd;
    __u64 off;
};


SWOLL_STRUCT_DEF(faccessat) {
    __u32  nr;
    __u64  dfd;
    char * filename;
    __u64  mode;
};

SWOLL_STRUCT_DEF(access) {
    __u32        nr;
    const char * filename;
    __u64        mode;
};

SWOLL_STRUCT_DEF(statx) {
    __u32          nr;
    __u64          dfd;
    char         * filename;
    __u64          flags;
    __u64          mask;
    struct statx * buffer;
};

SWOLL_STRUCT_DEF(syslog) {
    __u32  nr;
    __u64  type;
    char * buf;
    __s64  len;
};

SWOLL_STRUCT_DEF(fcntl) {
    __u32 nr;
    __s64 fd;
    __s64 cmd;
    __u64 arg;
};

SWOLL_STRUCT_DEF(fdatasync) {
    __u32 nr;
    __u64 fd;
};

SWOLL_STRUCT_DEF(fstatfs) {
    __u32           nr;
    __u64           fd;
    struct statfs * buf;
};

SWOLL_STRUCT_DEF(fsync) {
    __u32 nr;
    __u64 fd;
};

SWOLL_STRUCT_DEF(getcwd) {
    __u32  nr;
    char * buf;
    __u64  size;
};

SWOLL_STRUCT_DEF(getdents) {
    __u32                 nr;
    __u64                 fd;
    struct linux_dirent * dirent;
    __u64                 count;
};

SWOLL_STRUCT_DEF(inotify_add_watch) {
    __u32  nr;
    __u64  fd;
    char * pathname;
    __u64  mask;
};

SWOLL_STRUCT_DEF(listen) {
    __u32 nr;
    __u64 fd;
    __u64 backlog;
};

SWOLL_STRUCT_DEF(lookup_dcookie) {
    __u32  nr;
    __u64  cookie64;
    char * buf;
    __u64  len;
};

SWOLL_STRUCT_DEF(lseek) {
    __u32 nr;
    __u64 fd;
    __u64 offset;
    __u64 whence;
};

SWOLL_STRUCT_DEF(madvise) {
    __u32 nr;
    __u64 start;
    __u64 len_in;
    __u64 behavior;
};

SWOLL_STRUCT_DEF(membarrier) {
    __u32 nr;
    __u64 cmd;
    __u64 flags;
};

SWOLL_STRUCT_DEF(migrate_pages) {
    __u32   nr;
    __u64   pid;
    __u64   maxnode;
    __u64 * old_nodes;
    __u64 * new_nodes;
};

SWOLL_STRUCT_DEF(mkdir) {
    __u32  nr;
    char * pathname;
    __u64  mode;
};

SWOLL_STRUCT_DEF(mkdirat) {
    __u32  nr;
    __u64  dfd;
    char * pathname;
    __u64  mode;
};

SWOLL_STRUCT_DEF(mknod) {
    __u32  nr;
    char * filename;
    __u64  mode;
    __u64  dev;
};

SWOLL_STRUCT_DEF(mlock) {
    __u32 nr;
    __u64 start;
    __u64 len;
};

SWOLL_STRUCT_DEF(pivot_root) {
    __u32  nr;
    char * new_root;
    char * put_old;
};

SWOLL_STRUCT_DEF(poll) {
    __u32           nr;
    struct pollfd * ufds;
    __u64           nfds;
    __u64           timeout_msecs;
};

SWOLL_STRUCT_DEF(setns) {
    __s32 nr;
    __u64 fd;
    __u64 nstype;
};

SWOLL_STRUCT_DEF(socket) {
    __s32 nr;
    __u64 family;
    __u64 type;
    __u64 protocol;
};

SWOLL_STRUCT_DEF(prctl) {
    __u32 nr;
    __u64 option;
    __u64 arg2;
    __u64 arg3;
    __u64 arg4;
    __u64 arg5;
};

SWOLL_STRUCT_DEF(prlimit64) {
    __u32                   nr;
    __u64                   pid;
    __u64                   resource;
    const struct rlimit64 * new_rlim;
    struct rlimit64       * old_rlim;
};

SWOLL_STRUCT_DEF(recvmsg) {
    __u32                nr;
    __s64                fd;
    struct user_msghdr * msg;
    __u64                flags;
};


SWOLL_STRUCT_DEF(sendto) {
    __u32             nr;
    __u64             fd;
    void            * ubuf;
    __u64             size;
    __u64             flags;
    struct sockaddr * addr;
    __u64             addr_len;
};

SWOLL_STRUCT_DEF(recvfrom) {
    __u32             nr;
    __u64             fd;
    void            * ubuf;
    __u64             size;
    __u64             flags;
    struct sockaddr * addr;
    __u64           * addr_len;
};

SWOLL_STRUCT_DEF(setuid) {
    __u32 nr;
    __u64 uid;
};

SWOLL_STRUCT_DEF(setreuid) {
    __u32 nr;
    __u64 ruid;
    __u64 euid;
};

SWOLL_STRUCT_DEF(close) {
    __u32 nr;
    __u64 fd;
};

SWOLL_STRUCT_DEF(rmdir) {
    __u32        nr;
    const char * pathname;
};

SWOLL_STRUCT_DEF(ptrace) {
    __u32 nr;
    __u64 request;
    __u64 pid;
    __u64 addr;
    __u64 data;
};

SWOLL_STRUCT_DEF(chdir) {
    __u32        nr;
    const char * filename;
};


SWOLL_STRUCT_DEF(chroot) {
    __u32        nr;
    const char * filename;
};

SWOLL_STRUCT_DEF(link) {
    __u32        nr;
    const char * oldname;
    const char * newname;
};

SWOLL_STRUCT_DEF(readlink) {
    __u32        nr;
    const char * path;
    char       * buf;
    __u64        bufsiz;
};

SWOLL_STRUCT_DEF(readlinkat) {
    __u32        nr;
    __u64        dfd;
    const char * pathname;
    char       * buf;
    __u64        bufsiz;
};

SWOLL_STRUCT_DEF(symlink) {
    __u32        nr;
    const char * oldname;
    const char * newname;
};

SWOLL_STRUCT_DEF(getpeername) {
    __u32             nr;
    __u64             fd;
    struct sockaddr * usockaddr;
    __u64           * usockaddr_len;
};

SWOLL_STRUCT_DEF(getsockname) {
    __u32             nr;
    __u64             fd;
    struct sockaddr * usockaddr;
    __u64             usockaddr_len;
};

SWOLL_STRUCT_DEF(accept) {
    __u32             nr;
    __u64             fd;
    struct sockaddr * saddr;
    __u64           * saddr_len;
    __u64             flags;
};

SWOLL_STRUCT_DEF(mprotect) {
    __u32 nr;
    __u64 start;
    __u64 len;
    __u64 prot;
};

SWOLL_STRUCT_DEF(setsockopt) {
    __u32  nr;
    __u64  fd;
    __u64  level;
    __u64  optname;
    char * optval;
    __u64  optlen;
};

SWOLL_STRUCT_DEF(getsockopt) {
    __u32   nr;
    __u64   fd;
    __u64   level;
    __u64   optname;
    char  * optval;
    __u64 * optlen;
};

SWOLL_STRUCT_DEF(creat) {
    __u32        nr;
    const char * pathname;
    __u64        mode;
};

SWOLL_STRUCT_DEF(init_module) {
    __u32   nr;
    void  * umod;
    __u64   len;
    __u64 * uargs;
};

SWOLL_STRUCT_DEF(seccomp) {
    __u32        nr;
    __u64        op;
    __u64        flags;
    const char * uargs;
};

SWOLL_STRUCT_DEF(sethostname) {
    __u32  nr;
    char * name;
    __u64  len;
};

SWOLL_STRUCT_DEF(clone) {
    __u32   nr;
    __u64   flags;
    __u64   newsp;
    __u64 * parent_tidptr;
    __u64 * child_tidptr;
    __u64   tls;
};

SWOLL_STRUCT_DEF(read) {
    __u32  nr;
    __u64  fd;
    char * buf;
    __u64  count;
};

SWOLL_STRUCT_DEF(ioctl) {
    __u32 nr;
    __u64 fd;
    __u64 cmd;
    __u64 arg;
};

SWOLL_STRUCT_DEF(rename) {
    __u32        nr;
    const char * oldname;
    const char * newname;
};

SWOLL_STRUCT_DEF(timerfd_settime) {
    __u32                     nr;
    __u64                     flags;
    __u64                     ufd;
    const struct itimerspec * utmr;
    struct itimerspec       * otmr;
};

SWOLL_STRUCT_DEF(timerfd_create) {
    __u32 nr;
    __u64 clockid;
    __u64 flags;
};

SWOLL_STRUCT_DEF(mincore)
{
    __u32           nr;
    __u64           start;
    __u64           len;
    unsigned char * vec;
};

SWOLL_STRUCT_DEF(ftruncate)
{
    __u32 nr;
    __u64 fd;
    __u64 length;
};

SWOLL_STRUCT_DEF(nanosleep)
{
    __u32             nr;
    struct timespec * rqtp;
    struct timespec * rmtp;
};

SWOLL_STRUCT_DEF(rt_sigaction) {
    __u32              nr;
    __u64              sig;
    struct sigaction * act;
    struct sigaction * oact;
    __u64              sigsetsize;
};

SWOLL_STRUCT_DEF(write)
{
    __u32        nr;
    __u64        fd;
    const char * buf;
    __u64        count;
};

SWOLL_STRUCT_DEF(futex) {
    __u32             nr;
    __u64           * uaddr;
    __u64             op;
    __u64             val;
    struct timespec * utime;
    __u64           * uaddr2;
    __u64             val3;
};

SWOLL_STRUCT_DEF(select)
{
    __u32            nr;
    __u64            n;
    fd_set         * inp;
    fd_set         * outp;
    fd_set         * exp;
    struct timeval * tvp;
};

SWOLL_STRUCT_DEF(exit)
{
    __u32 nr;
    __u64 error_code;
};

struct swoll_event_args {
    struct swoll_event_args_common common;

    union {
        struct on_enter_args on_enter;
        struct on_exit_args  on_exit;
        SWOLL_STRUCT(kill);
        SWOLL_STRUCT(setuid);
        SWOLL_STRUCT(setreuid);
        SWOLL_STRUCT(recvmsg);
        SWOLL_STRUCT(recvfrom);
        SWOLL_STRUCT(sendto);
        SWOLL_STRUCT(access);
        SWOLL_STRUCT(mount);
        SWOLL_STRUCT(bind);
        SWOLL_STRUCT(socket);
        SWOLL_STRUCT(openat);
        SWOLL_STRUCT(open);
        SWOLL_STRUCT(connect);
        SWOLL_STRUCT(execve);
        SWOLL_STRUCT(unlink);
        SWOLL_STRUCT(unlinkat);
        SWOLL_STRUCT(epoll_wait);
        SWOLL_STRUCT(faccessat);
        SWOLL_STRUCT(statx);
        SWOLL_STRUCT(syslog);
        SWOLL_STRUCT(fcntl);
        SWOLL_STRUCT(fdatasync);
        SWOLL_STRUCT(fstatfs);
        SWOLL_STRUCT(fstat);
        SWOLL_STRUCT(stat);
        SWOLL_STRUCT(statfs);
        SWOLL_STRUCT(acct);
        SWOLL_STRUCT(alarm);
        SWOLL_STRUCT(brk);
        SWOLL_STRUCT(fsync);
        SWOLL_STRUCT(ftruncate);
        SWOLL_STRUCT(getcwd);
        SWOLL_STRUCT(getdents);
        SWOLL_STRUCT(listen);
        SWOLL_STRUCT(lseek);
        SWOLL_STRUCT(mkdir);
        SWOLL_STRUCT(mkdirat);
        SWOLL_STRUCT(mknod);
        SWOLL_STRUCT(mlock);
        SWOLL_STRUCT(madvise);
        SWOLL_STRUCT(membarrier);
        SWOLL_STRUCT(pivot_root);
        SWOLL_STRUCT(poll);
        SWOLL_STRUCT(prctl);
        SWOLL_STRUCT(migrate_pages);
        SWOLL_STRUCT(lookup_dcookie);
        SWOLL_STRUCT(sched_process_fork);
        SWOLL_STRUCT(inotify_add_watch);
        SWOLL_STRUCT(close);
        SWOLL_STRUCT(rmdir);
        SWOLL_STRUCT(ptrace);
        SWOLL_STRUCT(chdir);
        SWOLL_STRUCT(chroot);
        SWOLL_STRUCT(link);
        SWOLL_STRUCT(readlink);
        SWOLL_STRUCT(symlink);
        SWOLL_STRUCT(getpeername);
        SWOLL_STRUCT(getsockname);
        SWOLL_STRUCT(accept);
        SWOLL_STRUCT(mprotect);
        SWOLL_STRUCT(setsockopt);
        SWOLL_STRUCT(getsockopt);
        SWOLL_STRUCT(creat);
        SWOLL_STRUCT(init_module);
        SWOLL_STRUCT(seccomp);
        SWOLL_STRUCT(umount2);
        SWOLL_STRUCT(sethostname);
        SWOLL_STRUCT(clone);
        SWOLL_STRUCT(read);
        SWOLL_STRUCT(write);
        SWOLL_STRUCT(ioctl);
        SWOLL_STRUCT(rename);
        SWOLL_STRUCT(timerfd_settime);
        SWOLL_STRUCT(timerfd_create);
        SWOLL_STRUCT(mincore);
        SWOLL_STRUCT(nanosleep);
        SWOLL_STRUCT(rt_sigaction);
        SWOLL_STRUCT(futex);
        SWOLL_STRUCT(select);
        SWOLL_STRUCT(exit);
    };
};

struct swoll_event_key {
    struct on_enter_args on_enter;
    __u64                uid_gid;
    __u64                entr_timestamp;
};

struct swoll_metrics_key {
    __u32 pid_ns;  /* The PID namespace that this metric belongs to */
    __u32 syscall; /* Syscall NR */
    __u16 error;   /* Errno of the syscall (if non-zero) */
    __u16 pad;     /* for alignment */
};

struct swoll_metrics_val {
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

struct swoll_args {
    __u8 a0[EVENT_ARGSZ];
    __u8 a1[EVENT_ARGSZ];
    __u8 a2[EVENT_ARGSZ];
    __u8 a3[EVENT_ARGSZ];
    __u8 a4[EVENT_ARGSZ];
};

struct swoll_buf {
    __u8  buf[(EVENT_ARGSZ * EVENT_ARGNUM) - sizeof(uint32_t)];
    __u16 len;
    __u16 offset;
};

struct swoll_event {
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
        struct swoll_args _args;
        struct swoll_buf  _buff;
    };
};

#define EVENT_ARG0(ev) (ev)->_args.a0
#define EVENT_ARG1(ev) (ev)->_args.a1
#define EVENT_ARG2(ev) (ev)->_args.a2
#define EVENT_ARG3(ev) (ev)->_args.a3
#define EVENT_ARG4(ev) (ev)->_args.a4

/* we only want to bpf_probe_memset 0 out the byte NOT INCLUDING
 * the argument and comm arguments. Those we can just
 * zero out the first byte of each.
 */
#define BASE_EVENT_SZ sizeof(struct swoll_event) - (EVENT_ARGSZ * EVENT_ARGNUM) - TASK_COMM_LEN

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
SEC("maps/swoll_metrics") swoll_metrics =
{
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = sizeof(struct swoll_metrics_key),
    .value_size  = sizeof(struct swoll_metrics_val),
    .max_entries = 65535,
};


/**
 * swoll_evtable is where we emit sc_events to.
 */
struct bpf_map_def
SEC("maps/swoll_perf_output") swoll_perf_output =
{
    .type        = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size    = sizeof(__u32),
    .value_size  = sizeof(__u32),
    .max_entries = 2048,
    .pinning     = 0,
};

struct bpf_map_def
SEC("maps/swoll_state_map") swoll_state_map =
{
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = sizeof(__u64),
    .value_size  = sizeof(struct swoll_event_key),
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
 * @param "maps/swoll_event_scratch"
 *
 * @return
 */
struct bpf_map_def
SEC("maps/swoll_event_scratch") swoll_event_scratch =
{
    .type        = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size    = sizeof(__u32),
    .value_size  = sizeof(struct swoll_event),
    .max_entries = 1024,
};


#define SWOLL_FILTER_MODE_WHITELIST        (1 << 0)
#define SWOLL_FILTER_MODE_BLACKLIST        (1 << 1)
#define SWOLL_FILTER_MODE_GLOBAL_WHITELIST (1 << 2)
#define SWOLL_FILTER_MODE_GLOBAL_BLACKLIST (1 << 3)
#define SWOLL_FILTER_TYPE_SYSCALL          (1 << 13)
#define SWOLL_FILTER_TYPE_PID              (1 << 14)
#define SWOLL_FILTER_TYPE_PIDNS            (1 << 15)

#define SWOLL_FILTER_ALLOW                 0
#define SWOLL_FILTER_DROP                  1

typedef __u16 swoll_filter_type_t;
typedef __u8  swoll_offsetcfg_t;


struct swoll_filter_key {
    swoll_filter_type_t type; /* FILTER_TYPE_X|BL/WL */
    __u16               pad;
    __u32               ns;   /* optional PID namespace */
    __u32               key;
};

struct swoll_filter_val {
    __u64 sample_rate;
    __u64 sample_count;
};


struct bpf_map_def
SEC("maps/swoll_filter") swoll_filter =
{
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = sizeof(struct swoll_filter_key),
    .value_size  = sizeof(struct swoll_filter_val),
    .max_entries = 65535,
};

struct bpf_map_def
SEC("maps/swoll_filter_config") swoll_filter_config =
{
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = sizeof(swoll_filter_type_t),
    .value_size  = sizeof(__u8),
    .max_entries = 1024,
};

struct bpf_map_def
SEC("maps/swoll_offsets_config") swoll_offsets_config =
{
    .type        = BPF_MAP_TYPE_HASH,
    #define SK_OSCFG_NSPROXY 1
    #define SK_OSCFG_PIDNS   2
    .key_size    = sizeof(swoll_offsetcfg_t),
    .value_size  = sizeof(__u32),
    .max_entries = 2,
};

static _inline int
swoll__is_filter_enabled(swoll_filter_type_t type)
{
    __u8 * val = 0;

    if ((val = bpf_map_lookup_elem(&swoll_filter_config, &type))) {
        return *val == 0 ? 0 : 1;
    }

    return 0;
}

static _inline __u32
swoll__get_nsproxy_offset(void)
{
    __u32                 * val  = 0;
    swoll_offsetcfg_t const nspc = SK_OSCFG_NSPROXY;

    if ((val = bpf_map_lookup_elem(&swoll_offsets_config, (void *)&nspc))) {
        return *val;
    }

    return (__u32)offsetof(struct task_struct, nsproxy);
}

static _inline __u32
swoll__get_pid_ns_common_offset(void)
{
    __u32                 * val  = 0;
    swoll_offsetcfg_t const nsof = SK_OSCFG_PIDNS;

    if ((val = bpf_map_lookup_elem(&swoll_offsets_config, (void *)&nsof))) {
        return *val;
    }

    return (__u32)offsetof(struct pid_namespace, ns);
}

static _inline __u8
swoll__eval_filter(swoll_filter_type_t type, __u32 ns, __u32 key)
{
    if (swoll__is_filter_enabled(type)) {
        struct swoll_filter_key   fkey = {
            .type = type,
            .pad  = 0,
            .ns   = ns,
            .key  = key,
        };
        struct swoll_filter_val * val = NULL;

        if ((val = bpf_map_lookup_elem(&swoll_filter, &fkey)) != NULL) {
            if (val->sample_rate > 0) {
                val->sample_count++;

                D_("sampling[N:%u/K:%u]: count=%llu\n",
                                ns, key, val->sample_count);

                bpf_map_update_elem(&swoll_filter, &fkey, val, BPF_ANY);

                if ((val->sample_count > 1) && (val->sample_count % val->sample_rate)) {
                    D_("sampling[N:%u/K:%u/T:%d]: dropping...\n", ns, key, type);
                    return SWOLL_FILTER_DROP;
                }

                D_("sampling[N:%u/K:%u/T:%d]: permitting...\n", ns, key, type);
            }

            /* if the value was found in the table, and the lookup type is
             * a WHITELIST, then allow this. Otherwise, if the value was found
             * in the table, but the type is of BLACKLIST, then drop it.
             */
            return (type & (SWOLL_FILTER_MODE_GLOBAL_WHITELIST | SWOLL_FILTER_MODE_WHITELIST)) ?
                   SWOLL_FILTER_ALLOW : SWOLL_FILTER_DROP;
        }

        /* the value was NOT found in the table, so if it is of the type BLACKLIST,
         * we allow it (no entry in the blacklist table).
         */
        return (type & (SWOLL_FILTER_MODE_GLOBAL_BLACKLIST | SWOLL_FILTER_MODE_BLACKLIST)) ?
               SWOLL_FILTER_ALLOW : SWOLL_FILTER_DROP;
    }

    /* this filter type is not enabled in the configuration,
     * so we allow this event.
     */
    return SWOLL_FILTER_ALLOW;
}

static _inline struct pid *
swoll__task_pid(struct task_struct * task)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
    return _(task->thread_pid);
#else
    return _(task->pids[PIDTYPE_PID].pid);
#endif
}

static _inline struct pid_namespace *
swoll__ns_of_pid(struct pid * pid)
{
    struct pid_namespace * ns = NULL;

    if (pid) {
        ns = _(pid->numbers[_(pid->level)].ns);
    }

    return ns;
}

static _inline struct pid_namespace *
swoll__task_active_pid_ns(struct task_struct * tsk)
{
    return swoll__ns_of_pid(swoll__task_pid(tsk));
}

static _inline pid_t
swoll__pid_nr_ns(struct pid           * pid,
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
swoll__task_pid_nr_ns(struct task_struct   * task,
                      enum pid_type          type,
                      struct pid_namespace * ns)
{
    pid_t nr = 0;

    if (!ns) {
        ns = swoll__task_active_pid_ns(task);
    }

    if (type != PIDTYPE_PID) {
        if (type == __PIDTYPE_TGID) {
            type = PIDTYPE_PID;
        }

        task = _(task->group_leader);
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
    nr = swoll__pid_nr_ns(_(*task_pid_ptr(task, type)), ns);
#else
    nr = swoll__pid_nr_ns(_(task->pids[type].pid), ns);
#endif

    return nr;
}

/* virtual pid id (as seen from current) */
static _inline pid_t
swoll__task_pid_vnr(struct task_struct * task)
{
    return swoll__task_pid_nr_ns(task, PIDTYPE_PID, NULL);
}

/* the thread leader pid virtual id (the id seen from the pid namespace of
 * current
 */
static _inline pid_t
swoll__task_tgid_vnr(struct task_struct * task)
{
    return swoll__task_pid_nr_ns(task, __PIDTYPE_TGID, NULL);
}

static _inline pid_t
swoll__task_session_vnr(struct task_struct * task)
{
    return swoll__task_pid_nr_ns(task, PIDTYPE_SID, NULL);
}

static _inline pid_t
swoll__task_session_nr_ns(struct task_struct * task, struct pid_namespace * ns)
{
    return swoll__task_pid_nr_ns(task, PIDTYPE_SID, ns);
}

static _inline struct nsproxy *
swoll__task_nsproxy(struct task_struct * task)
{
    __u32            offset = swoll__get_nsproxy_offset();
    struct nsproxy * nsp;

    bpf_probe_memset(&nsp, 0, sizeof(nsp));

    if (bpf_probe_read(&nsp, sizeof(nsp), ((char *)task) + offset) == -EFAULT) {
        return NULL;
    }

    return nsp;
}

static _inline struct ns_common *
swoll__get_pid_ns_common(struct pid_namespace * pid, struct ns_common * out)
{
    __u32 offset = swoll__get_pid_ns_common_offset();

    bpf_probe_memset(out, 0, sizeof(*out));
    if (bpf_probe_read(out, sizeof(*out), ((char *)pid) + offset) == -EFAULT) {
        return NULL;
    }

    return out;
}

static _inline void
swoll__event_fill_namespaces(struct swoll_event * out, struct task_struct * task)
{
    struct nsproxy          * nsproxy = swoll__task_nsproxy(task);
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

    if (swoll__get_pid_ns_common(pid_ns, &pid_ns_common)) {
        out->pid_ns = pid_ns_common.inum;
    }
}

static _inline __u32
swoll__task_pid_namespace(struct task_struct * task)
{
    struct nsproxy       * nsproxy = swoll__task_nsproxy(task);
    struct pid_namespace * pid_ns  = _(nsproxy->pid_ns_for_children);
    struct ns_common       ns;

    if (swoll__get_pid_ns_common(pid_ns, &ns)) {
        return ns.inum;
    }

    return -1;
}

static _inline __u32
swoll__task_mnt_namespace(struct task_struct * task)
{
    struct nsproxy       * nsproxy = swoll__task_nsproxy(task);
    struct mnt_namespace * mnt_ns  = _(nsproxy->mnt_ns);
    struct ns_common     * ns;

    ns = &mnt_ns->ns;

    return _(ns->inum);
}

static _inline void
swoll__event_fill_init(struct swoll_event * ev, __u32 nr, struct task_struct * task)
{
    bpf_probe_memset(ev, 0, BASE_EVENT_SZ);

    swoll__event_fill_namespaces(ev, task);

    ev->syscall    = nr;
    ev->pid_tid    = bpf_get_current_pid_tgid();
    ev->uid_gid    = bpf_get_current_uid_gid();
    ev->session_id = swoll__task_session_vnr(task);
    ev->ns_pid     = swoll__task_tgid_vnr(task);
    ev->context_sw = _(task->nvcsw) + _(task->nivcsw);

    bpf_get_current_comm(ev->comm, sizeof(ev->comm));
}

static _inline long
swoll__syscall_get_nr(struct swoll_event_args * args)
{
    return args->on_enter.id;
}

static _inline __u8
swoll__run_filter(struct swoll_event_args * ctx)
{
    __u32                syscall_nr;
    __u32                tid;
    __u32                pidns;
    struct task_struct * task;
    int                  i;

    tid        = bpf_get_current_pid_tgid() >> 32;
    syscall_nr = swoll__syscall_get_nr(ctx);
    task       = (struct task_struct *)bpf_get_current_task();
    pidns      = swoll__task_pid_namespace(task);

    if (swoll__is_filter_enabled(SWOLL_FILTER_MODE_GLOBAL_WHITELIST | SWOLL_FILTER_TYPE_SYSCALL)) {
        if (swoll__eval_filter(SWOLL_FILTER_MODE_GLOBAL_WHITELIST | SWOLL_FILTER_TYPE_SYSCALL, 0, syscall_nr)) {
            /*D_("dropping key=%u\n", syscall_nr); */
            return SWOLL_FILTER_DROP;
        }
    } else {
        struct {
            swoll_filter_type_t t;
            __u32               ns;
            __u32               key;
        } evaluator[6] = {
            { SWOLL_FILTER_MODE_BLACKLIST | SWOLL_FILTER_TYPE_SYSCALL, pidns, syscall_nr },
            { SWOLL_FILTER_MODE_WHITELIST | SWOLL_FILTER_TYPE_SYSCALL, pidns, syscall_nr },
            { SWOLL_FILTER_MODE_BLACKLIST | SWOLL_FILTER_TYPE_PID,     0,     tid        },
            { SWOLL_FILTER_MODE_WHITELIST | SWOLL_FILTER_TYPE_PID,     0,     tid        },
            { SWOLL_FILTER_MODE_BLACKLIST | SWOLL_FILTER_TYPE_PIDNS,   0,     pidns      },
            { SWOLL_FILTER_MODE_WHITELIST | SWOLL_FILTER_TYPE_PIDNS,   0,     pidns      },
        };

#pragma unroll
        for (i = 0; i < 6; i++) {
            if (swoll__eval_filter(evaluator[i].t, evaluator[i].ns, evaluator[i].key)) {
                /*D_("dropping type=%u, ns=%u, key=%u\n", evaluator[i].t, evaluator[i].ns, evaluator[i].key); */
                return SWOLL_FILTER_DROP;
            }
        }
    }



    return SWOLL_FILTER_ALLOW;
}     /* swoll__run_filter */

#define METRICS_STATE_ENTER 0x01
#define METRICS_STATE_EXIT  0x02

static _inline struct swoll_metrics_val *
swoll__lookup_metrics(struct swoll_metrics_key * key)
{
    return (struct swoll_metrics_val *)bpf_map_lookup_elem(&swoll_metrics, key);
}

static _inline void
swoll__update_metrics(const __u32 pid_ns, const __u32 nr, const __s32 err)
{
    struct swoll_metrics_key   key         = { 0 };
    struct swoll_metrics_val * val;
    struct swoll_metrics_val   new_val     = { 0 };
    const __u64                ktime       = bpf_ktime_get_ns();
    __u64                      enter_ktime = 0;/*ktime; */

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
        if ((val = swoll__lookup_metrics(&key))) {
            enter_ktime = val->_enter_ktime;
        } else {
            enter_ktime = ktime;
        }

        key.error = err;
    }

    if ((val = swoll__lookup_metrics(&key))) {
        if (!err) {
            enter_ktime = val->_enter_ktime;
        }

        bpf_probe_memcpy(&new_val, val, sizeof(new_val));
        new_val.time += ktime - enter_ktime;
    } else {
        new_val.first_seen = ktime;
        new_val.time       = 0;
    }

    new_val.count    += 1;
    new_val.last_seen = ktime;


    bpf_map_update_elem(&swoll_metrics, &key, &new_val, BPF_ANY);
} /* swoll__update_metrics */

static _inline void
swoll__update_metrics_ktime(const __u32 pid_ns, const __u32 nr)
{
    struct swoll_metrics_key   key = {
        .pid_ns  = pid_ns,
        .syscall = nr,
        .error   = 0
    };
    struct swoll_metrics_val * val;
    struct swoll_metrics_val   new_val = { 0 };
    __u64                      ktime   = bpf_ktime_get_ns();

    if ((val = swoll__lookup_metrics(&key))) {
        bpf_probe_memcpy(&new_val, val, sizeof(new_val));
    } else {
        new_val.first_seen = ktime;
    }

    new_val._enter_ktime = ktime;

    bpf_map_update_elem(&swoll_metrics, &key, &new_val, BPF_ANY);
}

static _inline void
swoll__fill_metrics(struct swoll_event_args * ctx, __u8 state)
{
    if (ctx) {
        struct task_struct * task   = (struct task_struct *)bpf_get_current_task();
        __u32                pid_ns = swoll__task_pid_namespace(task);
        __u32                nr     = swoll__syscall_get_nr(ctx);

        if (nr == 0xFFFFFFFF) {
            return;
        }

        switch (state) {
            case METRICS_STATE_ENTER:
                /* upon syscall entry, we don't update stats quite yet,
                 * we wait for the EXIT state so we can calculate total
                 * time spent in each call.
                 */
                swoll__update_metrics_ktime(pid_ns, nr);
                break;
            case METRICS_STATE_EXIT:
            {
                __s32 err = (int)ctx->on_exit.ret < 0 ? -(int)ctx->on_exit.ret : 0;

                swoll__update_metrics(pid_ns, nr, err);
            }
            break;
        }
    }
}

#define SWOLL_CALL_DEF(TYPE) static _inline __u32          \
    swoll__fill_args_ ## TYPE(struct on_enter_args * args, \
            struct on_exit_args * eargs,                   \
            struct swoll_event * event)

#define SWOLL_CALL_INIT(TYPE)                \
    struct swoll_event_args_ ## TYPE * TYPE; \
                                             \
    if (!args || !event) {                   \
        return 2;                            \
    }                                        \
                                             \
    event->ret = eargs->ret;                 \
                                             \
    TYPE       = (struct swoll_event_args_ ## TYPE *)args



/**
 * use this to return from syscall-specific argument fillers
 * when the return value is the negated value of the errno
 * which will be sent to userspace.
 */
#define SWOLL_COMMON_LTZERO_ERROR (__u32)((int)eargs->ret < 0) ? -(int)eargs->ret : 0

/**
 * use this to return an error condition when a syscalls return
 * value is either NULL or not NULL.
 */
#define SWOLL_COMMON_NULL_ERROR   ((const char *)eargs->ret == NULL) ? (__u32) - 1 : 0


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
swoll__fill_default_nzeroret_args(struct on_exit_args * eargs)
{
    return SWOLL_COMMON_LTZERO_ERROR;
}

/**
 * @see swoll__fill_default_nzeroret_args
 *
 * @param eargs
 *
 * @return
 */
static _inline __u32
swoll__fill_default_nullret_args(struct on_exit_args * eargs)
{
    return SWOLL_COMMON_NULL_ERROR;
}

SWOLL_CALL_DEF(kill)
{
    SWOLL_CALL_INIT(kill);

    bpf_probe_memcpy(EVENT_ARG0(event), &kill->pid, sizeof(kill->pid));
    bpf_probe_memcpy(EVENT_ARG1(event), &kill->sig, sizeof(kill->sig));

    return SWOLL_COMMON_LTZERO_ERROR;
}

SWOLL_CALL_DEF(setuid)
{
    SWOLL_CALL_INIT(setuid);

    bpf_probe_memcpy(EVENT_ARG0(event), &setuid->uid, sizeof(setuid->uid));

    return SWOLL_COMMON_LTZERO_ERROR;
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

SWOLL_CALL_DEF(recvmsg)
{
    SWOLL_CALL_INIT(recvmsg);

    bpf_probe_memcpy(EVENT_ARG0(event), &recvmsg->fd, sizeof(recvmsg->fd));
    bpf_probe_read(EVENT_ARG1(event), sizeof(EVENT_ARG1(event)), (void *)recvmsg->msg);
    bpf_probe_memcpy(EVENT_ARG2(event), &recvmsg->flags, sizeof(recvmsg->flags));

    return SWOLL_COMMON_LTZERO_ERROR;
}

SWOLL_CALL_DEF(sendto)
{
    SWOLL_CALL_INIT(sendto);

    bpf_probe_memcpy(EVENT_ARG0(event), &sendto->fd, sizeof(sendto->fd));
    bpf_probe_read(EVENT_ARG1(event), sizeof(EVENT_ARG1(event)), (void *)sendto->ubuf);
    bpf_probe_memcpy(EVENT_ARG2(event), &sendto->size, sizeof(sendto->size));
    bpf_probe_memcpy(EVENT_ARG3(event), &sendto->flags, sizeof(sendto->flags));
    bpf_probe_read(EVENT_ARG4(event), sizeof(EVENT_ARG4(event)), (void *)sendto->addr);

    return SWOLL_COMMON_LTZERO_ERROR;
}


SWOLL_CALL_DEF(recvfrom)
{
    SWOLL_CALL_INIT(recvfrom);

    bpf_probe_memcpy(EVENT_ARG0(event), &recvfrom->fd, sizeof(recvfrom->fd));
    bpf_probe_read(EVENT_ARG1(event), sizeof(EVENT_ARG1(event)), (void *)recvfrom->ubuf);
    bpf_probe_memcpy(EVENT_ARG2(event), &recvfrom->size, sizeof(recvfrom->size));
    bpf_probe_memcpy(EVENT_ARG3(event), &recvfrom->flags, sizeof(recvfrom->flags));
    bpf_probe_read(EVENT_ARG4(event), sizeof(EVENT_ARG4(event)), (void *)recvfrom->addr);

    return SWOLL_COMMON_LTZERO_ERROR;
}

SWOLL_CALL_DEF(mount)
{
    SWOLL_CALL_INIT(mount);

    bpf_probe_read(EVENT_ARG0(event), sizeof(EVENT_ARG0(event)), (void *)mount->dev_name);
    bpf_probe_read(EVENT_ARG1(event), sizeof(EVENT_ARG1(event)), (void *)mount->dir_name);
    bpf_probe_read(EVENT_ARG2(event), sizeof(EVENT_ARG2(event)), (void *)mount->type);
    bpf_probe_memcpy(EVENT_ARG3(event), &mount->flags, sizeof(mount->flags));

    return SWOLL_COMMON_LTZERO_ERROR;
}

SWOLL_CALL_DEF(umount2)
{
    SWOLL_CALL_INIT(umount2);

    bpf_probe_read(EVENT_ARG0(event), sizeof(EVENT_ARG0(event)), (void *)umount2->name);
    bpf_probe_memcpy(EVENT_ARG1(event), &umount2->flags, sizeof(umount2->flags));

    return SWOLL_COMMON_LTZERO_ERROR;
}

SWOLL_CALL_DEF(access)
{
    SWOLL_CALL_INIT(access);

    bpf_probe_read(EVENT_ARG0(event), sizeof(EVENT_ARG0(event)), (void *)access->filename);
    bpf_probe_memcpy(EVENT_ARG1(event), &access->mode, sizeof(access->mode));

    return SWOLL_COMMON_LTZERO_ERROR;
}

SWOLL_CALL_DEF(prlimit64)
{
    SWOLL_CALL_INIT(prlimit64);

    bpf_probe_memcpy(EVENT_ARG0(event), &prlimit64->pid, sizeof(prlimit64->pid));
    bpf_probe_memcpy(EVENT_ARG1(event), &prlimit64->resource, sizeof(prlimit64->resource));
    bpf_probe_read(EVENT_ARG2(event), sizeof(EVENT_ARG2(event)), (void *)prlimit64->new_rlim);
    bpf_probe_read(EVENT_ARG3(event), sizeof(EVENT_ARG3(event)), (void *)prlimit64->old_rlim);

    return SWOLL_COMMON_LTZERO_ERROR;
}

SWOLL_CALL_DEF(setns)
{
    SWOLL_CALL_INIT(setns);

    bpf_probe_memcpy(EVENT_ARG0(event), &setns->fd, sizeof(setns->fd));
    bpf_probe_memcpy(EVENT_ARG1(event), &setns->nstype, sizeof(setns->nstype));

    return SWOLL_COMMON_LTZERO_ERROR;
}

SWOLL_CALL_DEF(bind)
{
    SWOLL_CALL_INIT(bind);

    bpf_probe_memcpy(EVENT_ARG0(event), &bind->fd, sizeof(bind->fd));
    bpf_probe_read(EVENT_ARG1(event), sizeof(EVENT_ARG1(event)), bind->umyaddr);
    bpf_probe_memcpy(EVENT_ARG2(event), &bind->addrlen, sizeof(bind->addrlen));

    return SWOLL_COMMON_LTZERO_ERROR;
}

SWOLL_CALL_DEF(socket)
{
    SWOLL_CALL_INIT(socket);

    bpf_probe_memcpy(EVENT_ARG0(event), &socket->family, sizeof(socket->family));
    bpf_probe_memcpy(EVENT_ARG1(event), &socket->type, sizeof(socket->type));
    bpf_probe_memcpy(EVENT_ARG2(event), &socket->protocol, sizeof(socket->protocol));

    return SWOLL_COMMON_LTZERO_ERROR;
}


SWOLL_CALL_DEF(openat)
{
    SWOLL_CALL_INIT(openat);

    bpf_probe_memcpy(EVENT_ARG0(event), &openat->dfd, sizeof(openat->dfd));
    bpf_probe_read(EVENT_ARG1(event), sizeof(EVENT_ARG1(event)), openat->filename);
    bpf_probe_memcpy(EVENT_ARG2(event), &openat->flags, sizeof(openat->flags));


    return SWOLL_COMMON_LTZERO_ERROR;
}

SWOLL_CALL_DEF(open)
{
    SWOLL_CALL_INIT(open);

    bpf_probe_read(EVENT_ARG0(event), sizeof(EVENT_ARG0(event)), open->filename);
    bpf_probe_memcpy(EVENT_ARG1(event), &open->flags, sizeof(open->flags));
    bpf_probe_memcpy(EVENT_ARG2(event), &open->mode, sizeof(open->mode));

    return SWOLL_COMMON_LTZERO_ERROR;
}

SWOLL_CALL_DEF(connect)
{
    SWOLL_CALL_INIT(connect);
    struct sockaddr * a = (void *)_(connect->uservaddr);

    bpf_probe_memcpy(EVENT_ARG0(event), &connect->fd, sizeof(connect->fd));
    bpf_probe_read(EVENT_ARG1(event), sizeof(EVENT_ARG1(event)), a);
    bpf_probe_memcpy(EVENT_ARG2(event), &connect->addrlen, sizeof(connect->addrlen));

    return SWOLL_COMMON_LTZERO_ERROR;
}


SWOLL_CALL_DEF(execve)
{
    SWOLL_CALL_INIT(execve);
    return SWOLL_COMMON_LTZERO_ERROR;
}

SWOLL_CALL_DEF(unlink)
{
    SWOLL_CALL_INIT(unlink);

    bpf_probe_read(EVENT_ARG0(event), sizeof(EVENT_ARG0(event)), unlink->pathname);

    return SWOLL_COMMON_LTZERO_ERROR;
}

SWOLL_CALL_DEF(unlinkat)
{
    SWOLL_CALL_INIT(unlinkat);

    bpf_probe_memcpy(EVENT_ARG0(event), &unlinkat->dfd, sizeof(unlinkat->dfd));
    bpf_probe_read(EVENT_ARG1(event), sizeof(EVENT_ARG1(event)), unlinkat->pathname);
    bpf_probe_memcpy(EVENT_ARG2(event), &unlinkat->offset, sizeof(unlinkat->offset));

    return SWOLL_COMMON_LTZERO_ERROR;
}

SWOLL_CALL_DEF(epoll_wait)
{
    SWOLL_CALL_INIT(epoll_wait);

    bpf_probe_memcpy(EVENT_ARG0(event), &epoll_wait->epfd, sizeof(epoll_wait->epfd));
    bpf_probe_memcpy(EVENT_ARG2(event), &epoll_wait->maxevents, sizeof(epoll_wait->maxevents));

    return SWOLL_COMMON_LTZERO_ERROR;
}

SWOLL_CALL_DEF(faccessat)
{
    SWOLL_CALL_INIT(faccessat);

    bpf_probe_memcpy(EVENT_ARG0(event), &faccessat->dfd, sizeof(faccessat->dfd));
    bpf_probe_read(EVENT_ARG1(event), sizeof(EVENT_ARG1(event)), faccessat->filename);
    bpf_probe_memcpy(EVENT_ARG2(event), &faccessat->mode, sizeof(faccessat->mode));

    return SWOLL_COMMON_LTZERO_ERROR;
}

SWOLL_CALL_DEF(statx)
{
    SWOLL_CALL_INIT(statx);

    bpf_probe_memcpy(EVENT_ARG0(event), &statx->dfd, sizeof(statx->dfd));
    bpf_probe_read(EVENT_ARG1(event), sizeof(EVENT_ARG1(event)), statx->filename);
    bpf_probe_memcpy(EVENT_ARG2(event), &statx->flags, sizeof(statx->flags));
    bpf_probe_memcpy(EVENT_ARG3(event), &statx->mask, sizeof(statx->mask));
    bpf_probe_read(EVENT_ARG4(event), sizeof(EVENT_ARG4(event)), statx->buffer);

    return SWOLL_COMMON_LTZERO_ERROR;
}

SWOLL_CALL_DEF(syslog)
{
    SWOLL_CALL_INIT(syslog);

    bpf_probe_memcpy(EVENT_ARG0(event), &syslog->type, sizeof(syslog->type));
    bpf_probe_read(EVENT_ARG1(event), sizeof(EVENT_ARG1(event)), syslog->buf);
    bpf_probe_memcpy(EVENT_ARG2(event), &syslog->len, sizeof(syslog->len));

    return SWOLL_COMMON_LTZERO_ERROR;
}

SWOLL_CALL_DEF(fcntl)
{
    SWOLL_CALL_INIT(fcntl);

    bpf_probe_memcpy(EVENT_ARG0(event), &fcntl->fd, sizeof(fcntl->fd));
    bpf_probe_memcpy(EVENT_ARG1(event), &fcntl->cmd, sizeof(fcntl->cmd));
    bpf_probe_memcpy(EVENT_ARG2(event), &fcntl->arg, sizeof(fcntl->arg));

    return SWOLL_COMMON_LTZERO_ERROR;
}

SWOLL_CALL_DEF(fdatasync)
{
    SWOLL_CALL_INIT(fdatasync);

    bpf_probe_memcpy(EVENT_ARG0(event), &fdatasync->fd, sizeof(fdatasync->fd));

    return SWOLL_COMMON_LTZERO_ERROR;
}

SWOLL_CALL_DEF(fstatfs)
{
    SWOLL_CALL_INIT(fstatfs);

    bpf_probe_memcpy(EVENT_ARG0(event), &fstatfs->fd, sizeof(fstatfs->fd));
    bpf_probe_read(EVENT_ARG1(event), sizeof(EVENT_ARG1(event)), fstatfs->buf);

    return SWOLL_COMMON_LTZERO_ERROR;
}

SWOLL_CALL_DEF(fstat)
{
    SWOLL_CALL_INIT(fstat);

    bpf_probe_memcpy(EVENT_ARG0(event), &fstat->fd, sizeof(fstat->fd));
    bpf_probe_read(EVENT_ARG1(event), sizeof(EVENT_ARG1(event)), fstat->statbuf);

    return SWOLL_COMMON_LTZERO_ERROR;
}

SWOLL_CALL_DEF(stat)
{
    SWOLL_CALL_INIT(stat);

    bpf_probe_read(EVENT_ARG0(event), sizeof(EVENT_ARG0(event)), (void *)stat->filename);
    bpf_probe_read(EVENT_ARG1(event), sizeof(EVENT_ARG1(event)), (void *)stat->statbuf);

    return SWOLL_COMMON_LTZERO_ERROR;
}

SWOLL_CALL_DEF(statfs)
{
    SWOLL_CALL_INIT(statfs);

    bpf_probe_read(EVENT_ARG0(event), sizeof(EVENT_ARG0(event)), (void *)statfs->pathname);
    bpf_probe_read(EVENT_ARG1(event), sizeof(EVENT_ARG1(event)), statfs->buf);

    return SWOLL_COMMON_LTZERO_ERROR;
}

SWOLL_CALL_DEF(acct)
{
    SWOLL_CALL_INIT(acct);

    bpf_probe_read(EVENT_ARG0(event), sizeof(EVENT_ARG0(event)), (void *)acct->pathname);

    return SWOLL_COMMON_LTZERO_ERROR;
}

SWOLL_CALL_DEF(alarm)
{
    SWOLL_CALL_INIT(alarm);

    bpf_probe_memcpy(EVENT_ARG0(event), &alarm->seconds, sizeof(alarm->seconds));

    return SWOLL_COMMON_LTZERO_ERROR;
}

SWOLL_CALL_DEF(brk)
{
    SWOLL_CALL_INIT(brk);

    bpf_probe_memcpy(EVENT_ARG0(event), &brk->addr, sizeof(brk->addr));

    return SWOLL_COMMON_LTZERO_ERROR;
}

SWOLL_CALL_DEF(fsync)
{
    SWOLL_CALL_INIT(fsync);

    bpf_probe_memcpy(EVENT_ARG0(event), &fsync->fd, sizeof(fsync->fd));

    return SWOLL_COMMON_LTZERO_ERROR;
}

SWOLL_CALL_DEF(ftruncate)
{
    SWOLL_CALL_INIT(ftruncate);

    bpf_probe_memcpy(EVENT_ARG0(event), &ftruncate->fd, sizeof(ftruncate->fd));
    bpf_probe_memcpy(EVENT_ARG1(event), &ftruncate->length, sizeof(ftruncate->length));

    return SWOLL_COMMON_LTZERO_ERROR;
}

SWOLL_CALL_DEF(getcwd)
{
    SWOLL_CALL_INIT(getcwd);

    bpf_probe_read(EVENT_ARG0(event), sizeof(EVENT_ARG0(event)), getcwd->buf);
    bpf_probe_memcpy(EVENT_ARG1(event), &getcwd->size, sizeof(getcwd->size));

    return SWOLL_COMMON_NULL_ERROR;
}

SWOLL_CALL_DEF(getdents)
{
    SWOLL_CALL_INIT(getdents);

    bpf_probe_memcpy(EVENT_ARG0(event), &getdents->fd, sizeof(getdents->fd));
    bpf_probe_memcpy(EVENT_ARG2(event), &getdents->count, sizeof(getdents->count));

    return SWOLL_COMMON_LTZERO_ERROR;
}

SWOLL_CALL_DEF(inotify_add_watch)
{
    SWOLL_CALL_INIT(inotify_add_watch);

    bpf_probe_memcpy(EVENT_ARG0(event), &inotify_add_watch->fd, sizeof(inotify_add_watch->fd));
    bpf_probe_read(EVENT_ARG1(event), sizeof(EVENT_ARG1(event)), inotify_add_watch->pathname);
    bpf_probe_memcpy(EVENT_ARG2(event), &inotify_add_watch->mask, sizeof(inotify_add_watch->mask));

    return SWOLL_COMMON_LTZERO_ERROR;
}

SWOLL_CALL_DEF(listen)
{
    SWOLL_CALL_INIT(listen);

    bpf_probe_memcpy(EVENT_ARG0(event), &listen->fd, sizeof(listen->fd));
    bpf_probe_memcpy(EVENT_ARG1(event), &listen->backlog, sizeof(listen->backlog));

    return SWOLL_COMMON_LTZERO_ERROR;
}

SWOLL_CALL_DEF(lookup_dcookie)
{
    SWOLL_CALL_INIT(lookup_dcookie);

    bpf_probe_memcpy(EVENT_ARG0(event), &lookup_dcookie->cookie64, sizeof(lookup_dcookie->cookie64));
    bpf_probe_memcpy(EVENT_ARG2(event), &lookup_dcookie->len, sizeof(lookup_dcookie->len));
    bpf_probe_read(EVENT_ARG1(event), sizeof(EVENT_ARG1(event)), lookup_dcookie->buf);

    return SWOLL_COMMON_LTZERO_ERROR;
}

SWOLL_CALL_DEF(lseek)
{
    SWOLL_CALL_INIT(lseek);

    bpf_probe_memcpy(EVENT_ARG0(event), &lseek->fd, sizeof(lseek->fd));
    bpf_probe_memcpy(EVENT_ARG1(event), &lseek->offset, sizeof(lseek->offset));
    bpf_probe_memcpy(EVENT_ARG2(event), &lseek->whence, sizeof(lseek->whence));

    return SWOLL_COMMON_LTZERO_ERROR;
}

SWOLL_CALL_DEF(madvise)
{
    SWOLL_CALL_INIT(madvise);

    bpf_probe_memcpy(EVENT_ARG0(event), &madvise->start, sizeof(madvise->start));
    bpf_probe_memcpy(EVENT_ARG1(event), &madvise->len_in, sizeof(madvise->len_in));
    bpf_probe_memcpy(EVENT_ARG2(event), &madvise->behavior, sizeof(madvise->behavior));

    return SWOLL_COMMON_LTZERO_ERROR;
}

SWOLL_CALL_DEF(membarrier)
{
    SWOLL_CALL_INIT(membarrier);

    bpf_probe_memcpy(EVENT_ARG0(event), &membarrier->cmd, sizeof(membarrier->cmd));
    bpf_probe_memcpy(EVENT_ARG1(event), &membarrier->flags, sizeof(membarrier->flags));

    return SWOLL_COMMON_LTZERO_ERROR;
}

SWOLL_CALL_DEF(mkdir)
{
    SWOLL_CALL_INIT(mkdir);

    bpf_probe_read(EVENT_ARG0(event), sizeof(EVENT_ARG0(event)), mkdir->pathname);
    bpf_probe_memcpy(EVENT_ARG1(event), &mkdir->mode, sizeof(mkdir->mode));

    return SWOLL_COMMON_LTZERO_ERROR;
}

SWOLL_CALL_DEF(mkdirat)
{
    SWOLL_CALL_INIT(mkdirat);

    bpf_probe_memcpy(EVENT_ARG0(event), &mkdirat->dfd, sizeof(mkdirat->dfd));
    bpf_probe_read(EVENT_ARG1(event), sizeof(EVENT_ARG1(event)), mkdirat->pathname);
    bpf_probe_memcpy(EVENT_ARG2(event), &mkdirat->mode, sizeof(mkdirat->mode));

    return SWOLL_COMMON_LTZERO_ERROR;
}

SWOLL_CALL_DEF(mknod)
{
    SWOLL_CALL_INIT(mknod);

    bpf_probe_read(EVENT_ARG0(event), sizeof(EVENT_ARG0(event)), mknod->filename);
    bpf_probe_memcpy(EVENT_ARG1(event), &mknod->mode, sizeof(mknod->mode));
    bpf_probe_memcpy(EVENT_ARG2(event), &mknod->dev, sizeof(mknod->dev));

    return SWOLL_COMMON_LTZERO_ERROR;
}

SWOLL_CALL_DEF(mlock)
{
    SWOLL_CALL_INIT(mlock);

    bpf_probe_memcpy(EVENT_ARG0(event), &mlock->start, sizeof(mlock->start));
    bpf_probe_memcpy(EVENT_ARG1(event), &mlock->len, sizeof(mlock->len));

    return SWOLL_COMMON_LTZERO_ERROR;
}

SWOLL_CALL_DEF(pivot_root)
{
    SWOLL_CALL_INIT(pivot_root);

    bpf_probe_read(EVENT_ARG0(event), sizeof(EVENT_ARG0(event)), pivot_root->new_root);
    bpf_probe_read(EVENT_ARG1(event), sizeof(EVENT_ARG1(event)), pivot_root->put_old);

    return SWOLL_COMMON_LTZERO_ERROR;
}

SWOLL_CALL_DEF(poll)
{
    SWOLL_CALL_INIT(poll);

    bpf_probe_memcpy(EVENT_ARG1(event), &poll->nfds, sizeof(poll->nfds));
    bpf_probe_memcpy(EVENT_ARG2(event), &poll->timeout_msecs, sizeof(poll->timeout_msecs));

    return SWOLL_COMMON_LTZERO_ERROR;
}

SWOLL_CALL_DEF(prctl)
{
    SWOLL_CALL_INIT(prctl);

    bpf_probe_memcpy(EVENT_ARG0(event), &prctl->option, sizeof(prctl->option));
    bpf_probe_memcpy(EVENT_ARG1(event), &prctl->arg2, sizeof(prctl->arg2));
    bpf_probe_memcpy(EVENT_ARG2(event), &prctl->arg3, sizeof(prctl->arg3));

    return SWOLL_COMMON_LTZERO_ERROR;
}

SWOLL_CALL_DEF(ptrace)
{
    SWOLL_CALL_INIT(ptrace);

    bpf_probe_memcpy(EVENT_ARG0(event), &ptrace->request, sizeof(ptrace->request));
    bpf_probe_memcpy(EVENT_ARG1(event), &ptrace->pid, sizeof(ptrace->pid));
    bpf_probe_memcpy(EVENT_ARG2(event), &ptrace->addr, sizeof(ptrace->addr));
    bpf_probe_memcpy(EVENT_ARG3(event), &ptrace->data, sizeof(ptrace->data));

    return SWOLL_COMMON_LTZERO_ERROR;
}

SWOLL_CALL_DEF(close)
{
    SWOLL_CALL_INIT(close);

    bpf_probe_memcpy(EVENT_ARG0(event), &close->fd, sizeof(close->fd));

    return SWOLL_COMMON_LTZERO_ERROR;
}

SWOLL_CALL_DEF(rmdir)
{
    SWOLL_CALL_INIT(rmdir);

    bpf_probe_read(EVENT_ARG0(event), sizeof(EVENT_ARG0(event)), (void *)rmdir->pathname);

    return SWOLL_COMMON_LTZERO_ERROR;
}

SWOLL_CALL_DEF(chdir)
{
    SWOLL_CALL_INIT(chdir);

    bpf_probe_read(EVENT_ARG0(event), sizeof(EVENT_ARG0(event)), (void *)chdir->filename);

    return SWOLL_COMMON_LTZERO_ERROR;
}

SWOLL_CALL_DEF(fchdir)
{
    SWOLL_CALL_INIT(fchdir);

    return SWOLL_COMMON_LTZERO_ERROR;
}

SWOLL_CALL_DEF(chroot)
{
    SWOLL_CALL_INIT(chroot);

    bpf_probe_read(EVENT_ARG0(event), sizeof(EVENT_ARG0(event)), (void *)chroot->filename);

    return SWOLL_COMMON_LTZERO_ERROR;
}

SWOLL_CALL_DEF(link)
{
    SWOLL_CALL_INIT(link);

    bpf_probe_read(EVENT_ARG0(event), sizeof(EVENT_ARG0(event)), (void *)link->oldname);
    bpf_probe_read(EVENT_ARG1(event), sizeof(EVENT_ARG1(event)), (void *)link->newname);

    return SWOLL_COMMON_LTZERO_ERROR;
}

SWOLL_CALL_DEF(linkat)
{
    SWOLL_CALL_INIT(linkat);

    return SWOLL_COMMON_LTZERO_ERROR;
}

SWOLL_CALL_DEF(symlink)
{
    SWOLL_CALL_INIT(symlink);

    bpf_probe_read(EVENT_ARG0(event), sizeof(EVENT_ARG0(event)), (void *)symlink->oldname);
    bpf_probe_read(EVENT_ARG1(event), sizeof(EVENT_ARG1(event)), (void *)symlink->newname);

    return SWOLL_COMMON_LTZERO_ERROR;
}

SWOLL_CALL_DEF(symlinkat)
{
    SWOLL_CALL_INIT(symlinkat);

    return SWOLL_COMMON_LTZERO_ERROR;
}


SWOLL_CALL_DEF(readlink)
{
    SWOLL_CALL_INIT(readlink);

    bpf_probe_read(EVENT_ARG0(event), sizeof(EVENT_ARG0(event)), (void *)readlink->path);
    bpf_probe_read(EVENT_ARG1(event), sizeof(EVENT_ARG1(event)), (void *)readlink->buf);
    bpf_probe_memcpy(EVENT_ARG2(event), &readlink->bufsiz, sizeof(readlink->bufsiz));

    return SWOLL_COMMON_LTZERO_ERROR;
}

SWOLL_CALL_DEF(readlinkat)
{
    SWOLL_CALL_INIT(readlinkat);

    bpf_probe_memcpy(EVENT_ARG0(event), &readlinkat->dfd, sizeof(readlinkat->dfd));
    bpf_probe_read(EVENT_ARG1(event), sizeof(EVENT_ARG0(event)), (void *)readlinkat->pathname);
    bpf_probe_read(EVENT_ARG2(event), sizeof(EVENT_ARG1(event)), (void *)readlinkat->buf);
    bpf_probe_memcpy(EVENT_ARG3(event), &readlinkat->bufsiz, sizeof(readlinkat->bufsiz));

    return SWOLL_COMMON_LTZERO_ERROR;
}

SWOLL_CALL_DEF(getpeername)
{
    SWOLL_CALL_INIT(getpeername);

    bpf_probe_memcpy(EVENT_ARG0(event), &getpeername->fd, sizeof(getpeername->fd));
    bpf_probe_read(EVENT_ARG1(event), sizeof(EVENT_ARG1(event)), getpeername->usockaddr);
    bpf_probe_memcpy(EVENT_ARG2(event), &getpeername->usockaddr_len, sizeof(getpeername->usockaddr_len));

    return SWOLL_COMMON_LTZERO_ERROR;
}

SWOLL_CALL_DEF(getsockname)
{
    SWOLL_CALL_INIT(getsockname);

    bpf_probe_memcpy(EVENT_ARG0(event), &getsockname->fd, sizeof(getsockname->fd));
    bpf_probe_read(EVENT_ARG1(event), sizeof(EVENT_ARG1(event)), getsockname->usockaddr);
    bpf_probe_memcpy(EVENT_ARG2(event), &getsockname->usockaddr_len, sizeof(getsockname->usockaddr_len));

    return SWOLL_COMMON_LTZERO_ERROR;
}

SWOLL_CALL_DEF(accept)
{
    SWOLL_CALL_INIT(accept);

    bpf_probe_memcpy(EVENT_ARG0(event), &accept->fd, sizeof(accept->fd));
    bpf_probe_read(EVENT_ARG1(event), sizeof(EVENT_ARG1(event)), accept->saddr);
    bpf_probe_memcpy(EVENT_ARG2(event), &accept->saddr_len, sizeof(accept->saddr_len));

    return SWOLL_COMMON_LTZERO_ERROR;
}

SWOLL_CALL_DEF(accept4)
{
    SWOLL_CALL_INIT(accept);

    bpf_probe_memcpy(EVENT_ARG0(event), &accept->fd, sizeof(accept->fd));
    bpf_probe_read(EVENT_ARG1(event), sizeof(EVENT_ARG1(event)), accept->saddr);
    bpf_probe_memcpy(EVENT_ARG2(event), &accept->saddr_len, sizeof(accept->saddr_len));
    bpf_probe_memcpy(EVENT_ARG3(event), &accept->flags, sizeof(accept->flags));

    return SWOLL_COMMON_LTZERO_ERROR;
}

SWOLL_CALL_DEF(mprotect)
{
    SWOLL_CALL_INIT(mprotect);

    bpf_probe_memcpy(EVENT_ARG0(event), &mprotect->start, sizeof(mprotect->start));
    bpf_probe_memcpy(EVENT_ARG1(event), &mprotect->len, sizeof(mprotect->len));
    bpf_probe_memcpy(EVENT_ARG2(event), &mprotect->prot, sizeof(mprotect->prot));
    bpf_probe_read(EVENT_ARG3(event), sizeof(EVENT_ARG3(event)), (void *)mprotect->start);

    return SWOLL_COMMON_LTZERO_ERROR;
}

SWOLL_CALL_DEF(setsockopt)
{
    SWOLL_CALL_INIT(setsockopt);

    bpf_probe_memcpy(EVENT_ARG0(event), &setsockopt->fd, sizeof(setsockopt->fd));
    bpf_probe_memcpy(EVENT_ARG1(event), &setsockopt->level, sizeof(setsockopt->level));
    bpf_probe_memcpy(EVENT_ARG2(event), &setsockopt->optname, sizeof(setsockopt->optname));
    bpf_probe_read(EVENT_ARG3(event), sizeof(EVENT_ARG3(event)), setsockopt->optval);
    bpf_probe_memcpy(EVENT_ARG4(event), &setsockopt->optlen, sizeof(setsockopt->optlen));

    return SWOLL_COMMON_LTZERO_ERROR;
}

SWOLL_CALL_DEF(getsockopt)
{
    SWOLL_CALL_INIT(getsockopt);

    bpf_probe_memcpy(EVENT_ARG0(event), &getsockopt->fd, sizeof(getsockopt->fd));
    bpf_probe_memcpy(EVENT_ARG1(event), &getsockopt->level, sizeof(getsockopt->level));
    bpf_probe_memcpy(EVENT_ARG2(event), &getsockopt->optname, sizeof(getsockopt->optname));
    bpf_probe_read(EVENT_ARG3(event), sizeof(__u64), getsockopt->optval);
    bpf_probe_read(EVENT_ARG4(event), sizeof(__u64 *), getsockopt->optlen);

    return SWOLL_COMMON_LTZERO_ERROR;
}


SWOLL_CALL_DEF(creat)
{
    SWOLL_CALL_INIT(creat);

    bpf_probe_read(EVENT_ARG0(event), sizeof(EVENT_ARG0(event)), (void *)creat->pathname);
    bpf_probe_memcpy(EVENT_ARG1(event), &creat->mode, sizeof(creat->mode));

    return SWOLL_COMMON_LTZERO_ERROR;
}

SWOLL_CALL_DEF(init_module)
{
    SWOLL_CALL_INIT(init_module);

    bpf_probe_read(EVENT_ARG0(event), sizeof(EVENT_ARG0(event)), init_module->umod);
    bpf_probe_memcpy(EVENT_ARG1(event), &init_module->len, sizeof(init_module->len));
    bpf_probe_read(EVENT_ARG2(event), sizeof(EVENT_ARG2(event)), init_module->uargs);

    return SWOLL_COMMON_LTZERO_ERROR;
}

SWOLL_CALL_DEF(seccomp)
{
    SWOLL_CALL_INIT(seccomp);

    bpf_probe_memcpy(EVENT_ARG0(event), &seccomp->op, sizeof(seccomp->op));
    bpf_probe_memcpy(EVENT_ARG1(event), &seccomp->flags, sizeof(seccomp->flags));
    bpf_probe_read(EVENT_ARG2(event), sizeof(EVENT_ARG2(event)), (void *)seccomp->uargs);

    return SWOLL_COMMON_LTZERO_ERROR;
}

SWOLL_CALL_DEF(sethostname)
{
    SWOLL_CALL_INIT(sethostname);

    bpf_probe_read(EVENT_ARG0(event), sizeof(EVENT_ARG0(event)), (void *)sethostname->name);
    bpf_probe_memcpy(EVENT_ARG1(event), &sethostname->len, sizeof(sethostname->len));

    return SWOLL_COMMON_LTZERO_ERROR;
}

SWOLL_CALL_DEF(clone)
{
    SWOLL_CALL_INIT(clone);

    bpf_probe_memcpy(EVENT_ARG0(event), &clone->flags, sizeof(clone->flags));
    bpf_probe_memcpy(EVENT_ARG1(event), &clone->newsp, sizeof(clone->newsp));
    bpf_probe_read(EVENT_ARG2(event), sizeof(EVENT_ARG2(event)), (void *)clone->parent_tidptr);
    bpf_probe_read(EVENT_ARG3(event), sizeof(EVENT_ARG3(event)), (void *)clone->child_tidptr);
    bpf_probe_memcpy(EVENT_ARG4(event), &clone->tls, sizeof(clone->tls));

    return SWOLL_COMMON_LTZERO_ERROR;
}

SWOLL_CALL_DEF(read)
{
    SWOLL_CALL_INIT(read);

    bpf_probe_memcpy(EVENT_ARG0(event), &read->fd, sizeof(read->fd));
    bpf_probe_read(EVENT_ARG1(event), sizeof(EVENT_ARG1(event)), (void *)read->buf);
    bpf_probe_memcpy(EVENT_ARG2(event), &read->count, sizeof(read->count));

    return SWOLL_COMMON_LTZERO_ERROR;
}

SWOLL_CALL_DEF(write)
{
    SWOLL_CALL_INIT(write);

    bpf_probe_memcpy(EVENT_ARG0(event), &write->fd, sizeof(write->fd));
    bpf_probe_read(EVENT_ARG1(event), sizeof(EVENT_ARG1(event)), (void *)write->buf);
    bpf_probe_memcpy(EVENT_ARG2(event), &write->count, sizeof(write->count));

    return SWOLL_COMMON_LTZERO_ERROR;
}

SWOLL_CALL_DEF(ioctl)
{
    SWOLL_CALL_INIT(ioctl);

    bpf_probe_memcpy(EVENT_ARG0(event), &ioctl->fd, sizeof(ioctl->fd));
    bpf_probe_memcpy(EVENT_ARG1(event), &ioctl->cmd, sizeof(ioctl->cmd));
    bpf_probe_read(EVENT_ARG2(event), sizeof(EVENT_ARG2(event)), (void *)ioctl->arg);

    return SWOLL_COMMON_LTZERO_ERROR;
}

SWOLL_CALL_DEF(rename)
{
    SWOLL_CALL_INIT(rename);

    bpf_probe_read(EVENT_ARG0(event), sizeof(EVENT_ARG0(event)), (void *)rename->oldname);
    bpf_probe_read(EVENT_ARG1(event), sizeof(EVENT_ARG1(event)), (void *)rename->newname);

    return SWOLL_COMMON_LTZERO_ERROR;
}

SWOLL_CALL_DEF(timerfd_settime)
{
    SWOLL_CALL_INIT(timerfd_settime);

    bpf_probe_memcpy(EVENT_ARG0(event), &timerfd_settime->ufd, sizeof(timerfd_settime->ufd));
    bpf_probe_memcpy(EVENT_ARG1(event), &timerfd_settime->flags, sizeof(timerfd_settime->flags));
    bpf_probe_read(EVENT_ARG2(event), sizeof(EVENT_ARG2(event)), (void *)timerfd_settime->utmr);
    bpf_probe_read(EVENT_ARG3(event), sizeof(EVENT_ARG3(event)), (void *)timerfd_settime->otmr);

    return SWOLL_COMMON_LTZERO_ERROR;
}

SWOLL_CALL_DEF(timerfd_create)
{
    SWOLL_CALL_INIT(timerfd_create);

    bpf_probe_memcpy(EVENT_ARG0(event), &timerfd_create->clockid, sizeof(timerfd_create->clockid));
    bpf_probe_memcpy(EVENT_ARG1(event), &timerfd_create->flags, sizeof(timerfd_create->flags));

    return SWOLL_COMMON_LTZERO_ERROR;
}

SWOLL_CALL_DEF(mincore)
{
    SWOLL_CALL_INIT(mincore);

    bpf_probe_memcpy(EVENT_ARG0(event), &mincore->start, sizeof(mincore->start));
    bpf_probe_memcpy(EVENT_ARG1(event), &mincore->len, sizeof(mincore->len));
    bpf_probe_read(EVENT_ARG2(event), sizeof(EVENT_ARG2(event)), (void *)mincore->vec);

    return SWOLL_COMMON_LTZERO_ERROR;
}


SWOLL_CALL_DEF(nanosleep)
{
    SWOLL_CALL_INIT(nanosleep);

    bpf_probe_read(EVENT_ARG0(event), sizeof(EVENT_ARG0(event)), (void *)nanosleep->rqtp);
    bpf_probe_read(EVENT_ARG1(event), sizeof(EVENT_ARG1(event)), (void *)nanosleep->rmtp);

    return SWOLL_COMMON_LTZERO_ERROR;
}

SWOLL_CALL_DEF(rt_sigaction)
{
    SWOLL_CALL_INIT(rt_sigaction);

    bpf_probe_memcpy(EVENT_ARG0(event), &rt_sigaction->sig, sizeof(rt_sigaction->sig));
    bpf_probe_read(EVENT_ARG1(event), sizeof(EVENT_ARG1(event)), (void *)rt_sigaction->act);
    bpf_probe_read(EVENT_ARG2(event), sizeof(EVENT_ARG2(event)), (void *)rt_sigaction->oact);
    bpf_probe_memcpy(EVENT_ARG3(event), &rt_sigaction->sigsetsize, sizeof(rt_sigaction->sigsetsize));

    return SWOLL_COMMON_LTZERO_ERROR;
}

SWOLL_CALL_DEF(futex)
{
    SWOLL_CALL_INIT(futex);

    bpf_probe_memcpy(EVENT_ARG0(event), &futex->uaddr, sizeof(futex->uaddr));
    bpf_probe_memcpy(EVENT_ARG1(event), &futex->op, sizeof(futex->op));
    bpf_probe_memcpy(EVENT_ARG2(event), &futex->val, sizeof(futex->val));
    bpf_probe_memcpy(EVENT_ARG3(event), &futex->utime, sizeof(futex->utime));
    bpf_probe_memcpy(EVENT_ARG4(event), &futex->uaddr2, sizeof(futex->uaddr2));

    return SWOLL_COMMON_LTZERO_ERROR;
}

SWOLL_CALL_DEF(select)
{
    SWOLL_CALL_INIT(select);

    bpf_probe_memcpy(EVENT_ARG0(event), &select->n, sizeof(select->n));
    bpf_probe_memcpy(EVENT_ARG1(event), &select->inp, sizeof(select->inp));
    bpf_probe_memcpy(EVENT_ARG2(event), &select->outp, sizeof(select->outp));
    bpf_probe_memcpy(EVENT_ARG3(event), &select->exp, sizeof(select->exp));
    bpf_probe_memcpy(EVENT_ARG4(event), &select->tvp, sizeof(select->tvp));

    return SWOLL_COMMON_LTZERO_ERROR;
}

SWOLL_CALL_DEF(umask)
{
    SWOLL_CALL_INIT(umask);

    return SWOLL_COMMON_LTZERO_ERROR;
}

SWOLL_CALL_DEF(exit)
{
    SWOLL_CALL_INIT(exit);

    bpf_probe_memcpy(EVENT_ARG0(event), &exit->error_code, sizeof(exit->error_code));

    return SWOLL_COMMON_LTZERO_ERROR;
}


SEC("tracepoint/raw_syscalls/sys_enter") int
swoll__enter(struct swoll_event_args * ctx)
{
    __u64                  pid_tid    = bpf_get_current_pid_tgid();
    __u32                  syscall_nr = swoll__syscall_get_nr(ctx);
    struct swoll_event_key ev_key;

#ifndef SWOLL__NO_METRICS
    swoll__fill_metrics(ctx, METRICS_STATE_ENTER);
#endif

#ifdef SWOLL__METRICS_ONLY
    /* compiled with metrics-only, so yeah... just return */
    return 0;
#endif

    /* since we have a static tracepoint specifically for execve, we can safely
     * ignore this.
     */
    if (syscall_nr == __NR_execve) {
        return 0;
    }

    if (swoll__run_filter(ctx) == SWOLL_FILTER_DROP) {
        return 0;
    }

    bpf_probe_memset(&ev_key, 0, sizeof(struct swoll_event_key));
    bpf_probe_memcpy(&ev_key.on_enter, &ctx->on_enter, sizeof(struct on_enter_args));

    ev_key.uid_gid        = bpf_get_current_uid_gid();
    ev_key.entr_timestamp = bpf_ktime_get_ns();

    bpf_map_update_elem(&swoll_state_map, &pid_tid, &ev_key, BPF_ANY);

    return 0;
}     /* swoll__enter */

SEC("tracepoint/raw_syscalls/sys_exit") int
swoll__exit(struct swoll_event_args * ctx)
{
    __u64                    pid_tid;
    __u32                    cpu;
    struct swoll_event_key * ev_key;
    struct swoll_event     * event;
    struct task_struct     * task;

#ifndef SWOLL__NO_METRICS
    swoll__fill_metrics(ctx, METRICS_STATE_EXIT);
#endif

#ifdef SWOLL__METRICS_ONLY
    /* metrics only, return... */
    return 0;
#endif

    pid_tid = bpf_get_current_pid_tgid();

    if ((ev_key = bpf_map_lookup_elem(&swoll_state_map, &pid_tid)) == NULL) {
        return 0;
    }

    cpu = bpf_get_smp_processor_id();

    if ((event = bpf_map_lookup_elem(&swoll_event_scratch, &cpu)) == NULL) {
        bpf_map_delete_elem(&swoll_state_map, &pid_tid);
        return 0;
    }

    /* make sure we're looking at the same syscall..... */
    if (ctx->on_exit.id != ev_key->on_enter.id) {
        bpf_map_delete_elem(&swoll_state_map, &pid_tid);
        return 0;
    }

    task = (struct task_struct *)bpf_get_current_task();

    swoll__event_fill_init(event, ev_key->on_enter.id, task);
    swoll__event_fill_namespaces(event, task);

    event->uid_gid   = ev_key->uid_gid;
    event->entr_usec = ev_key->entr_timestamp;
    event->exit_usec = bpf_ktime_get_ns();

    #define SWOLL_CALL(TYPE)                                                        \
        case __NR_ ## TYPE:                                                         \
            event->errno =                                                          \
                swoll__fill_args_ ## TYPE(&ev_key->on_enter, &ctx->on_exit, event); \
            break

    switch (event->syscall) {
        SWOLL_CALL(kill);
        SWOLL_CALL(acct);
        SWOLL_CALL(alarm);
        SWOLL_CALL(brk);
        SWOLL_CALL(close);
        SWOLL_CALL(access);
        SWOLL_CALL(openat);
        SWOLL_CALL(open);
        SWOLL_CALL(connect);
        SWOLL_CALL(execve);
        SWOLL_CALL(unlink);
        SWOLL_CALL(unlinkat);
        SWOLL_CALL(epoll_wait);
        SWOLL_CALL(faccessat);
        SWOLL_CALL(statx);
        SWOLL_CALL(syslog);
        SWOLL_CALL(fcntl);
        SWOLL_CALL(fdatasync);
        SWOLL_CALL(fstatfs);
        SWOLL_CALL(fstat);
        SWOLL_CALL(statfs);
        SWOLL_CALL(fsync);
        SWOLL_CALL(ftruncate);
        SWOLL_CALL(getcwd);
        SWOLL_CALL(getdents);
        SWOLL_CALL(inotify_add_watch);
        SWOLL_CALL(listen);
        SWOLL_CALL(lookup_dcookie);
        SWOLL_CALL(lseek);
        SWOLL_CALL(madvise);
        SWOLL_CALL(membarrier);
        SWOLL_CALL(mkdir);
        SWOLL_CALL(mkdirat);
        SWOLL_CALL(mknod);
        SWOLL_CALL(mlock);
        SWOLL_CALL(pivot_root);
        SWOLL_CALL(poll);
        SWOLL_CALL(prctl);
        SWOLL_CALL(rmdir);
        SWOLL_CALL(chdir);
        SWOLL_CALL(fchdir);
        SWOLL_CALL(chroot);
        SWOLL_CALL(link);
        SWOLL_CALL(linkat);
        SWOLL_CALL(symlink);
        SWOLL_CALL(symlinkat);
        SWOLL_CALL(bind);
        SWOLL_CALL(socket);
        SWOLL_CALL(setns);
        SWOLL_CALL(prlimit64);
        SWOLL_CALL(mount);
        SWOLL_CALL(umount2);
        SWOLL_CALL(recvmsg);
        SWOLL_CALL(setuid);
        SWOLL_CALL(recvfrom);
        SWOLL_CALL(sendto);
        SWOLL_CALL(ptrace);
        SWOLL_CALL(readlink);
        SWOLL_CALL(readlinkat);
        SWOLL_CALL(getpeername);
        SWOLL_CALL(getsockname);
        SWOLL_CALL(accept);
        SWOLL_CALL(accept4);
        SWOLL_CALL(mprotect);
        SWOLL_CALL(setsockopt);
        SWOLL_CALL(getsockopt);
        SWOLL_CALL(creat);
        SWOLL_CALL(init_module);
        SWOLL_CALL(seccomp);
        SWOLL_CALL(stat);
        SWOLL_CALL(sethostname);
        SWOLL_CALL(clone);
        SWOLL_CALL(read);
        SWOLL_CALL(write);
        SWOLL_CALL(ioctl);
        SWOLL_CALL(rename);
        SWOLL_CALL(timerfd_settime);
        SWOLL_CALL(timerfd_create);
        SWOLL_CALL(mincore);
        SWOLL_CALL(nanosleep);
        SWOLL_CALL(rt_sigaction);
        SWOLL_CALL(futex);
        SWOLL_CALL(select);
        SWOLL_CALL(exit);
        default:
            EVENT_ARG0(event)[0] = '\0';
            EVENT_ARG1(event)[0] = '\0';
            EVENT_ARG2(event)[0] = '\0';
            EVENT_ARG3(event)[0] = '\0';
            EVENT_ARG4(event)[0] = '\0';
            swoll__fill_default_nzeroret_args(&ctx->on_exit);
            break;
    }     /* switch */

    bpf_perf_event_output(ctx, &swoll_perf_output,
            BPF_F_CURRENT_CPU, event, sizeof(struct swoll_event));
    bpf_map_delete_elem(&swoll_state_map, &pid_tid);

    return 0;
}     /* swoll__exit */

SEC("tracepoint/syscalls/sys_enter_execve") int
swoll__syscalls_execve(struct swoll_event_args * ctx)
{
#ifdef SWOLL__METRICS_ONLY
    /* handled by sys_enter tracepoint */
    return 0;
#endif
    struct swoll_event * event = NULL;
    __u32                cpu   = bpf_get_smp_processor_id();
    __u64                tid   = bpf_get_current_pid_tgid() >> 32;
    struct task_struct * task  = (struct task_struct *)bpf_get_current_task();

    if (swoll__run_filter(ctx) == SWOLL_FILTER_DROP) {
        return 0;
    }

    if ((event = bpf_map_lookup_elem(&swoll_event_scratch, &cpu)) == NULL) {
        return 0;
    }

    swoll__event_fill_init(event, __NR_execve, task);
    swoll__event_fill_namespaces(event, task);

    event->entr_usec = event->exit_usec = bpf_ktime_get_ns();

    bpf_probe_read(EVENT_ARG0(event), sizeof(EVENT_ARG0(event)), (void *)ctx->execve.filename);
    bpf_probe_read(EVENT_ARG1(event), sizeof(EVENT_ARG1(event)), _(ctx->execve.argv[1]));
    bpf_probe_read(EVENT_ARG2(event), sizeof(EVENT_ARG2(event)), _(ctx->execve.argv[2]));
    bpf_probe_read(EVENT_ARG3(event), sizeof(EVENT_ARG3(event)), _(ctx->execve.argv[3]));
    bpf_probe_read(EVENT_ARG4(event), sizeof(EVENT_ARG4(event)), _(ctx->execve.argv[4]));

    bpf_perf_event_output(ctx, &swoll_perf_output,
            BPF_F_CURRENT_CPU, event, sizeof(struct swoll_event));

    return 0;
}     /* swoll__syscalls_execve */

__u8 _license[] SEC("license") = "GPL";
__u32 _version  SEC("version") = 0xFFFFFFFE;
