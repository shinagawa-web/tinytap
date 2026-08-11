#ifndef TINYTAP_DROPS_H
#define TINYTAP_DROPS_H

enum drop_reason {
    DROP_RINGBUF    = 0,
    DROP_MAP_FULL   = 1,
    DROP_REASON_MAX = 2,
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, DROP_REASON_MAX);
    __type(key, __u32);
    __type(value, __u64);
} drop_counters SEC(".maps");

static __always_inline void count_drop(__u32 reason)
{
    __u64 *c = bpf_map_lookup_elem(&drop_counters, &reason);
    if (c)
        (*c)++;
}

#endif
