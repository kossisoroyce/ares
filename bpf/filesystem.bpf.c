// SPDX-License-Identifier: Apache-2.0
// Filesystem integrity sensor (spec 7.3, 8.1).
//
// Uses LSM hooks where available (spec 8.1) to observe writes/renames/attr
// changes to protected paths. Path filtering is applied in userspace against
// the configured protected_paths to keep the BPF program small; the program
// forwards candidate events and the userspace loader drops uninteresting ones.
//
// NOTE: requires a kernel built with BPF LSM (CONFIG_BPF_LSM=y) and
// lsm.s/lsm attach support. Falls back to fanotify/inotify in userspace when
// unavailable.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define PATH_LEN 256

struct file_event {
    __u32 pid;
    __u32 uid;
    __u8  op; // 0=open-write 1=unlink 2=rename 3=chmod
    char  comm[16];
    char  path[PATH_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} file_events SEC(".maps");

static __always_inline void fill_common(struct file_event *e, __u8 op)
{
    __u64 id = bpf_get_current_pid_tgid();
    e->pid = id >> 32;
    e->uid = bpf_get_current_uid_gid();
    e->op = op;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

SEC("lsm/path_unlink")
int BPF_PROG(handle_unlink, const struct path *dir, struct dentry *dentry)
{
    struct file_event *e = bpf_ringbuf_reserve(&file_events, sizeof(*e), 0);
    if (!e)
        return 0;
    fill_common(e, 1);
    bpf_probe_read_kernel_str(&e->path, sizeof(e->path),
                              BPF_CORE_READ(dentry, d_name.name));
    bpf_ringbuf_submit(e, 0);
    return 0; // observe-only: never deny (spec 13.1 initial no-block posture)
}

SEC("lsm/path_chmod")
int BPF_PROG(handle_chmod, const struct path *path, umode_t mode)
{
    struct file_event *e = bpf_ringbuf_reserve(&file_events, sizeof(*e), 0);
    if (!e)
        return 0;
    fill_common(e, 3);
    bpf_probe_read_kernel_str(&e->path, sizeof(e->path),
                              BPF_CORE_READ(path, dentry, d_name.name));
    bpf_ringbuf_submit(e, 0);
    return 0;
}
