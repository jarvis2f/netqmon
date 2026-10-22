/* SPDX-License-Identifier: Apache-2.0
 * Read-only Stage 2 path evidence in the real Agent. No policy attribution.
 */
#ifndef NETQMON_QOS_PATH_PROBE_H
#define NETQMON_QOS_PATH_PROBE_H
struct qos_path_key {
    __u32 ifindex;
    __u32 hook;
    __u32 priority;
    __u32 mark;
    __u32 skb_iif;
    __u16 ether_type;
    __u8 vlan_depth;
    __u8 reserved;
    __u8 source_mac[6];
    __u8 destination_mac[6];
    __u16 vlan_outer;
    __u16 vlan_inner;
};
struct qos_path_value {
    __u64 packets;
    __u64 bytes;
};
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} qos_path_control SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct qos_path_key);
    __type(value, struct qos_path_value);
} qos_path_frames SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} qos_path_overflow SEC(".maps");

static __attribute__((noinline)) void qos_path_observe_record(struct __sk_buff *skb, __u32 hook)
{
    __u32 zero = 0;
    void *data = (void *)(long)skb->data;
    void *end = (void *)(long)skb->data_end;
    struct ethernet_header *eth = data;
    if ((void *)(eth + 1) > end)
        return;
    struct qos_path_key key = {};
    key.ifindex = skb->ifindex;
    key.hook = hook;
    key.priority = skb->priority;
    key.mark = skb->mark;
    key.skb_iif = skb->ingress_ifindex;
    key.ether_type = netqmon_ntohs(eth->protocol);
    __builtin_memcpy(key.source_mac, eth->source, 6);
    __builtin_memcpy(key.destination_mac, eth->destination, 6);
    __u8 *cursor = data + sizeof(*eth);
#pragma unroll
    for (int i = 0; i < MAX_VLAN_HEADERS; i++) {
        if (key.ether_type != ETH_P_8021Q && key.ether_type != ETH_P_8021AD)
            break;
        struct vlan_header *vlan = (void *)cursor;
        if ((void *)(vlan + 1) > end)
            return;
        if (i == 0)
            key.vlan_outer = netqmon_ntohs(vlan->tci);
        else
            key.vlan_inner = netqmon_ntohs(vlan->tci);
        key.vlan_depth++;
        key.ether_type = netqmon_ntohs(vlan->encapsulated_protocol);
        cursor += sizeof(*vlan);
    }
    struct qos_path_value *value = bpf_map_lookup_elem(&qos_path_frames, &key);
    if (!value) {
        struct qos_path_value initial = {};
        bpf_map_update_elem(&qos_path_frames, &key, &initial, BPF_NOEXIST);
        value = bpf_map_lookup_elem(&qos_path_frames, &key);
    }
    if (value) {
        __sync_fetch_and_add(&value->packets, 1);
        __sync_fetch_and_add(&value->bytes, skb->len);
    } else {
        __u64 *lost = bpf_map_lookup_elem(&qos_path_overflow, &zero);
        if (lost)
            __sync_fetch_and_add(lost, 1);
    }
}

static __always_inline void qos_path_observe(struct __sk_buff *skb, __u32 hook)
{
    __u32 zero = 0;
    __u32 *enabled = bpf_map_lookup_elem(&qos_path_control, &zero);
    if (!enabled || !*enabled)
        return;
    qos_path_observe_record(skb, hook);
}

SEC("tc")
int netqmon_qos_path_egress(struct __sk_buff *skb)
{
    qos_path_observe(skb, NETQMON_HOOK_EGRESS);
    return -1; /* Read-only observer: continue existing classification. */
}
#endif
