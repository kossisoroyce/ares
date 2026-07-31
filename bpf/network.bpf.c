// SPDX-License-Identifier: Apache-2.0
// Outbound connection sensor (spec 7.2, 8.1).
//
// Hooks tcp_connect via fentry to record outbound connection attempts,
// including failed ones, before the socket may be torn down. Pushes records to
// a ring buffer drained by the userspace loader.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

struct net_event {
    __u32 pid;
    __u32 uid;
    __u32 saddr;
    __u32 daddr;
    __u16 dport;
    __u16 sport;
    __u8  family;
    char  comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} net_events SEC(".maps");

SEC("fentry/tcp_connect")
int BPF_PROG(trace_tcp_connect, struct sock *sk)
{
    struct net_event *e = bpf_ringbuf_reserve(&net_events, sizeof(*e), 0);
    if (!e)
        return 0;

    __u64 id = bpf_get_current_pid_tgid();
    e->pid = id >> 32;
    e->uid = bpf_get_current_uid_gid();
    e->family = BPF_CORE_READ(sk, __sk_common.skc_family);
    e->daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    e->saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    e->dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
    e->sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}
