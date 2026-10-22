/* SPDX-License-Identifier: Apache-2.0
 * Compile-time opt-in instrumentation. Not a policy-enforcement backend.
 */
#ifndef NETQMON_QOS_POC_H
#define NETQMON_QOS_POC_H

struct qos_poc_config {
    __u32 abi_version;
    __u32 lan_ifindex;
    __u32 ifb_ifindex;
    __u32 enabled;
    __u32 ingress_ifindex;
    __u8 client_v4[4];
    __u8 remote_v4[4];
    __u8 client_v6[16];
    __u8 remote_v6[16];
};

struct qos_poc_observation {
    __u64 packets;
    __u64 bytes;
    __u32 mark;
    __u32 priority;
    __u32 ifindex;
    __u32 skb_iif;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct qos_poc_config);
} qos_poc_config_map SEC(".maps");

/* ingress before/after classification, IFB egress, LAN egress before/after,
 * and the non-direct-action matcher immediately before mirred. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 6);
    __type(key, __u32);
    __type(value, struct qos_poc_observation);
} qos_poc_observations SEC(".maps");

static __always_inline struct qos_poc_config *qos_poc_config(void)
{
    __u32 zero = 0;
    struct qos_poc_config *config = bpf_map_lookup_elem(&qos_poc_config_map, &zero);
    return config && config->abi_version == NETQMON_QOS_POC_ABI_VERSION &&
           config->enabled ? config : 0;
}

static __always_inline void qos_poc_observe(struct __sk_buff *skb, __u32 slot)
{
    struct qos_poc_observation *value = bpf_map_lookup_elem(&qos_poc_observations, &slot);
    if (value) {
        __sync_fetch_and_add(&value->packets, 1);
        __sync_fetch_and_add(&value->bytes, skb->len);
        value->mark = skb->mark;
        value->priority = skb->priority;
        value->ifindex = skb->ifindex;
        value->skb_iif = skb->ingress_ifindex;
    }
}

/* Exact test endpoints only. This intentionally does not infer application
 * identities, classify arbitrary client networks, or advertise QoS support. */
static __always_inline int qos_poc_equal(const __u8 *a, const __u8 *b, int size)
{
    if (size == 4) {
        __u32 left, right;
        __builtin_memcpy(&left, a, sizeof(left));
        __builtin_memcpy(&right, b, sizeof(right));
        return left == right;
    }
    __u64 left[2], right[2];
    __builtin_memcpy(left, a, sizeof(left));
    __builtin_memcpy(right, b, sizeof(right));
    return left[0] == right[0] && left[1] == right[1];
}

static __always_inline int qos_poc_direction(struct __sk_buff *skb,
                                             struct qos_poc_config *config)
{
    void *data = (void *)(long)skb->data;
    void *end = (void *)(long)skb->data_end;
    struct ethernet_header *eth = data;
    if ((void *)(eth + 1) > end)
        return 0;
    __u8 *cursor = data + sizeof(*eth);
    __u16 protocol = netqmon_ntohs(eth->protocol);
#pragma unroll
    for (int i = 0; i < MAX_VLAN_HEADERS; i++) {
        if (protocol != ETH_P_8021Q && protocol != ETH_P_8021AD)
            break;
        struct vlan_header *vlan = (void *)cursor;
        if ((void *)(vlan + 1) > end)
            return 0;
        protocol = netqmon_ntohs(vlan->encapsulated_protocol);
        cursor += sizeof(*vlan);
    }
    if (protocol == ETH_P_IP) {
        struct ipv4_header *ip = (void *)cursor;
        if ((void *)(ip + 1) > end)
            return 0;
        if (qos_poc_equal((__u8 *)&ip->source, config->client_v4, 4) &&
            qos_poc_equal((__u8 *)&ip->destination, config->remote_v4, 4))
            return 1;
        if (qos_poc_equal((__u8 *)&ip->destination, config->client_v4, 4) &&
            qos_poc_equal((__u8 *)&ip->source, config->remote_v4, 4))
            return 2;
    } else if (protocol == ETH_P_IPV6) {
        struct ipv6_header *ip = (void *)cursor;
        if ((void *)(ip + 1) > end)
            return 0;
        if (qos_poc_equal(ip->source, config->client_v6, 16) &&
            qos_poc_equal(ip->destination, config->remote_v6, 16))
            return 1;
        if (qos_poc_equal(ip->destination, config->client_v6, 16) &&
            qos_poc_equal(ip->source, config->remote_v6, 16))
            return 2;
    }
    return 0;
}

static __attribute__((noinline)) int qos_poc_ingress(struct __sk_buff *skb)
{
    struct qos_poc_config *config = qos_poc_config();
    if (!config || skb->ifindex != config->ingress_ifindex ||
        qos_poc_direction(skb, config) != 1)
        return TC_ACT_OK;
    qos_poc_observe(skb, 0);
    skb->priority = NETQMON_QOS_CLASSID(NETQMON_QOS_UPLOAD_MAJOR,
                                       NETQMON_QOS_POC_LEAF_MINOR);
    qos_poc_observe(skb, 1);
    return -1; /* TC_ACT_UNSPEC / TCX_NEXT: reach the mirred matcher. */
}

static __attribute__((noinline)) void qos_poc_egress(struct __sk_buff *skb)
{
    struct qos_poc_config *config = qos_poc_config();
    if (!config || skb->ifindex != config->lan_ifindex)
        return;
    int direction = qos_poc_direction(skb, config);
    /* Only the exact client-facing download tuple consumes that budget.
     * SNAT and proxy-created upstream sockets may erase upload metadata;
     * all other LAN egress traffic explicitly takes the real bypass leaf.
     * Neither skb_iif nor an upstream proxy tuple is an application identity. */
    qos_poc_observe(skb, 3);
    if (direction == 2)
        skb->priority = NETQMON_QOS_CLASSID(NETQMON_QOS_DOWNLOAD_MAJOR,
                                          NETQMON_QOS_POC_LEAF_MINOR);
    else
        skb->priority = NETQMON_QOS_CLASSID(NETQMON_QOS_DOWNLOAD_MAJOR,
                                          NETQMON_QOS_BYPASS_MINOR);
    qos_poc_observe(skb, 4);
}

SEC("tc")
int netqmon_qos_poc_match(struct __sk_buff *skb)
{
    struct qos_poc_config *config = qos_poc_config();
    if (!config || skb->ifindex != config->ingress_ifindex ||
        skb->priority != NETQMON_QOS_CLASSID(NETQMON_QOS_UPLOAD_MAJOR,
                                            NETQMON_QOS_POC_LEAF_MINOR) ||
        qos_poc_direction(skb, config) != 1)
        return 0;
    qos_poc_observe(skb, 5);
    return -1; /* Match the configured non-direct-action mirred extension. */
}

SEC("tc")
int netqmon_qos_poc_ifb(struct __sk_buff *skb)
{
    struct qos_poc_config *config = qos_poc_config();
    if (config && skb->ifindex == config->ifb_ifindex)
        qos_poc_observe(skb, 2);
    return -1;
}

/* One-arm capture runs on bridge members. Classify at the bridge's actual
 * shaping egress without introducing a second accounting/sampling hook. */
SEC("tc")
int netqmon_qos_poc_lan_egress(struct __sk_buff *skb)
{
    qos_poc_egress(skb);
    return -1;
}
#endif
