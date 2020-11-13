/* this file contains the base maps and functions needed in order to
 * pass any test that involves loading the BPF object.
 */

#undef asm_volatile_goto
#define asm_volatile_goto(...) asm volatile ("stuff")


#include <linux/types.h>
#include <linux/version.h>
#include <linux/ptrace.h>
#include <linux/bpf.h>
#include <syscall.h>
#include <linux/utsname.h>
#include <limits.h>

#include "../../../internal/bpf/bpf.h"


#define DUMMYVAL                          \
    {                                     \
        .type        = BPF_MAP_TYPE_HASH, \
        .key_size    = 1,                 \
        .value_size  = 1,                 \
        .max_entries = 1,                 \
    }

struct bpf_map_def SEC("maps/sk_metrics") sk_metrics             = DUMMYVAL;
struct bpf_map_def SEC("maps/sk_state_map") sk_state_map         = DUMMYVAL;
struct bpf_map_def SEC("maps/sk_event_scratch") sk_event_scratch = DUMMYVAL;
struct bpf_map_def SEC("maps/sk_filter_config") sk_filter_config = DUMMYVAL;
struct bpf_map_def SEC("maps/sk_filter") sk_filter = DUMMYVAL;

struct bpf_map_def
SEC("maps/sk_perf_output") sk_perf_output =
{
    .type        = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size    = sizeof(int),
    .value_size  = sizeof(int),
    .max_entries = 1024,
};

SEC("tracepoint/raw_syscalls/sys_enter") int
__senter(void * ctx)
{
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit") int
__sexit(void * ctx)
{
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve") int
__sexecve(void * ctx)
{
    return 0;
}
