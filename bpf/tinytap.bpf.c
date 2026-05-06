//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("kprobe/__arm64_sys_accept4")
int handle_accept4(void *ctx)
{
    bpf_printk("tinytap: accept4 called\n");
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
