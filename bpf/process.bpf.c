// SPDX-License-Identifier: Apache-2.0
// Process execution/exit sensor (spec 8.1).
//
// CO-RE eBPF program. Attaches to the sched_process_exec / sched_process_exit
// tracepoints and pushes compact process records to a ring buffer that the
// userspace loader (src/ares/sensors/ebpf) drains. This is the preferred
// Linux collector; it captures short-lived processes the procfs poller misses.
//
// Build (on a Linux host with libbpf + clang):
//   clang -O2 -g -target bpf -c bpf/process.bpf.c -o process.bpf.o

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL"; // required for many BPF helpers

#define ARGV_LEN 256
#define COMM_LEN 16
#define PATH_LEN 256

struct process_event {
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    __u64 start_time_ns;
    __u8  is_exit;
    char  comm[COMM_LEN];
    char  filename[PATH_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16 MiB ring buffer (spec 8.1)
} events SEC(".maps");

SEC("tracepoint/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    struct process_event *e;
    struct task_struct *task;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0; // ring buffer full -> userspace records a drop

    __u64 id = bpf_get_current_pid_tgid();
    e->pid = id >> 32;
    e->uid = bpf_get_current_uid_gid();
    e->gid = bpf_get_current_uid_gid() >> 32;
    e->is_exit = 0;
    e->start_time_ns = bpf_ktime_get_ns();

    task = (struct task_struct *)bpf_get_current_task();
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // filename offset lives at __data_loc in the tracepoint context.
    unsigned fname_off = ctx->__data_loc_filename & 0xFFFF;
    bpf_probe_read_str(&e->filename, sizeof(e->filename), (void *)ctx + fname_off);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template *ctx)
{
    struct process_event *e;

    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;
    __u32 tid = (__u32)id;
    if (pid != tid)
        return 0; // only report thread-group leader exit

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;
    e->pid = pid;
    e->is_exit = 1;
    e->start_time_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
    return 0;
}
