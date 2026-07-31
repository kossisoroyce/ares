# eBPF sensors

These CO-RE eBPF programs are the preferred Linux collectors (spec 8.1). They
compile only on a Linux host with the BPF toolchain — editor/clang warnings
about `vmlinux.h` and `__u32` on non-Linux machines are expected and harmless.

## Prerequisites (Linux)

- Kernel ≥ 5.8 with BTF (`/sys/kernel/btf/vmlinux`)
- `clang`, `llvm`, `libbpf-dev`, `bpftool`
- For `filesystem.bpf.c`: a kernel built with `CONFIG_BPF_LSM=y`

## Generate vmlinux.h and build

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -c bpf/process.bpf.c -o process.bpf.o
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -c bpf/network.bpf.c -o network.bpf.o
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -c bpf/filesystem.bpf.c -o filesystem.bpf.o
```

The userspace loader in `src/ares/sensors/ebpf/` attaches the compiled
objects and drains their ring buffers. When eBPF is unavailable the daemon
falls back to the procfs/psutil sensors (spec 8.2), which run everywhere.
