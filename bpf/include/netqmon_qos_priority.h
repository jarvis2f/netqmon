/* SPDX-License-Identifier: Apache-2.0
 * Experimental client budget classifier. No mark writes or app inference.
 * Userspace publishes immutable inner maps only after class readback.
 */
#ifndef NETQMON_QOS_PRIORITY_H
#define NETQMON_QOS_PRIORITY_H
struct qos_client_key {
    __u8 mac[6];
    __u8 reserved[2];
};
struct qos_client_assignment {
    __u32 slot;
    __u32 delivery_ifindex;
    __u32 flags;
    __u32 generation;
    __u64 expires_ns;
    __u32 upload_classid;
    __u32 download_classid;
};
struct qos_client_map {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __uint(map_flags, BPF_F_RDONLY_PROG);
    __type(key, struct qos_client_key);
    __type(value, struct qos_client_assignment);
};
struct qos_client_map qos_clients_empty SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __uint(max_entries, 1);
    __type(key, __u32);
    __array(values, struct qos_client_map);
} qos_clients_active SEC(".maps") = {
    .values = { [0] = &qos_clients_empty },
};
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} qos_priority_ifb SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32);
    __type(key, __u32);
    __type(value, __u8);
} qos_priority_ingress_ports SEC(".maps");
/* Remains populated until each actual root has been removed. An empty client
 * map must still explicitly bypass download budgets while roots exist. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32);
    __type(key, __u32);
    __type(value, __u8);
} qos_priority_roots SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, struct qos_path_value);
} qos_priority_counters SEC(".maps");

/* Internet-scoped client blocks must leave configured LAN, routed-LAN and
 * tunnel networks reachable. Separate LPM tries keep v4/v6 lookups exact. */
struct qos_internal_prefix_key {
    __u32 prefixlen;
    __u8 address[16];
};
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 256);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct qos_internal_prefix_key);
    __type(value, __u8);
} qos_internal_v4 SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 256);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct qos_internal_prefix_key);
    __type(value, __u8);
} qos_internal_v6 SEC(".maps");

#define QOS_CLIENT_UPLOAD 1
#define QOS_CLIENT_DOWNLOAD 2
#define QOS_CLIENT_BLOCK 4

static __always_inline void qos_priority_count(struct __sk_buff *skb, __u32 slot)
{
    struct qos_path_value *counter = bpf_map_lookup_elem(&qos_priority_counters, &slot);
    if (counter) {
        __sync_fetch_and_add(&counter->packets, 1);
        __sync_fetch_and_add(&counter->bytes, skb->len);
    }
}

static __always_inline struct qos_client_assignment *qos_priority_client(struct __sk_buff *skb, int upload)
{
    __u32 zero = 0;
    void *clients = bpf_map_lookup_elem(&qos_clients_active, &zero);
    if (!clients)
        return 0;
    void *data = (void *)(long)skb->data;
    void *end = (void *)(long)skb->data_end;
    struct ethernet_header *eth = data;
    if ((void *)(eth + 1) > end)
        return 0;
    struct qos_client_key key = {};
    if (upload)
        __builtin_memcpy(key.mac, eth->source, 6);
    else
        __builtin_memcpy(key.mac, eth->destination, 6);
    return bpf_map_lookup_elem(clients, &key);
}

static __always_inline int qos_priority_assignment_valid(struct qos_client_assignment *client)
{
    if (client->slot > NETQMON_QOS_CLIENT_LAST - NETQMON_QOS_CLIENT_FIRST ||
        !client->generation || (client->flags & ~(QOS_CLIENT_UPLOAD | QOS_CLIENT_DOWNLOAD | QOS_CLIENT_BLOCK)))
        return 0;
    __u32 minor = NETQMON_QOS_DEFAULT_FIRST + client->slot;
    return minor <= NETQMON_QOS_DEFAULT_LAST &&
        client->upload_classid == NETQMON_QOS_CLASSID(NETQMON_QOS_UPLOAD_MAJOR, minor) &&
        client->download_classid == NETQMON_QOS_CLASSID(NETQMON_QOS_DOWNLOAD_MAJOR, minor) &&
        (!(client->flags & QOS_CLIENT_DOWNLOAD) || client->delivery_ifindex);
}

/* Return true only for routed IP packets outside all configured internal
 * prefixes. Non-IP control traffic stays available; malformed IP is dropped
 * for a blocked client so parser uncertainty cannot create an Internet bypass. */
static __attribute__((noinline)) int qos_priority_is_internet_packet(
    struct __sk_buff *skb, int source_address)
{
    void *data = (void *)(long)skb->data;
    void *end = (void *)(long)skb->data_end;
    struct ethernet_header *eth = data;
    if ((void *)(eth + 1) > end)
        return 1;
    __u16 protocol = netqmon_ntohs(eth->protocol);
    __u8 *cursor = (void *)(eth + 1);
#pragma unroll
    for (int depth = 0; depth < MAX_VLAN_HEADERS; depth++) {
        if (protocol != ETH_P_8021Q && protocol != ETH_P_8021AD)
            break;
        struct vlan_header *vlan = (void *)cursor;
        if ((void *)(vlan + 1) > end)
            return 1;
        protocol = netqmon_ntohs(vlan->encapsulated_protocol);
        cursor += sizeof(*vlan);
    }
    if (protocol == ETH_P_IP) {
        struct ipv4_header *ip = (void *)cursor;
        if ((void *)(ip + 1) > end || (ip->version_ihl >> 4) != 4)
            return 1;
        struct qos_internal_prefix_key key = {.prefixlen = 32};
        if (source_address)
            __builtin_memcpy(key.address, &ip->source, 4);
        else
            __builtin_memcpy(key.address, &ip->destination, 4);
        return bpf_map_lookup_elem(&qos_internal_v4, &key) == 0;
    }
    if (protocol == ETH_P_IPV6) {
        struct ipv6_header *ip = (void *)cursor;
        if ((void *)(ip + 1) > end || (ip->version_traffic_class >> 4) != 6)
            return 1;
        struct qos_internal_prefix_key key = {.prefixlen = 128};
        if (source_address)
            __builtin_memcpy(key.address, ip->source, 16);
        else
            __builtin_memcpy(key.address, ip->destination, 16);
        return bpf_map_lookup_elem(&qos_internal_v6, &key) == 0;
    }
    return 0;
}

static __always_inline int qos_priority_application_classid_valid(__u32 classid,
                                                                    __u32 major,
                                                                    __u32 slot)
{
    __u32 minor = classid & 0xffff;
    if ((classid >> 16) != major ||
        minor < NETQMON_QOS_APPLICATION_FIRST ||
        minor > NETQMON_QOS_APPLICATION_LAST)
        return 0;
    return (minor - NETQMON_QOS_APPLICATION_FIRST) /
        NETQMON_QOS_APPLICATIONS_PER_CLIENT == slot;
}

static __always_inline int qos_priority_upload_classid_valid(__u32 classid)
{
    __u32 major = classid >> 16;
    __u32 minor = classid & 0xffff;
    /* 52:200..2ff is reserved for upload client slots. The slot remains
     * available after L3 routing rewrites the Ethernet source MAC. */
    return major == NETQMON_QOS_UPLOAD_MAJOR &&
        ((minor >= NETQMON_QOS_DEFAULT_FIRST && minor <= NETQMON_QOS_DEFAULT_LAST) ||
         (minor >= NETQMON_QOS_APPLICATION_FIRST && minor <= NETQMON_QOS_APPLICATION_LAST));
}

#define NETQMON_QOS_MIRRED_CB_MAGIC 0x4e514d52U

static __attribute__((noinline)) int qos_priority_ingress(struct __sk_buff *skb)
{
    __u32 zero = 0, ifindex = skb->ifindex;
    __u32 *ifb = bpf_map_lookup_elem(&qos_priority_ifb, &zero);
    if (!bpf_map_lookup_elem(&qos_priority_ingress_ports, &ifindex))
        return TC_ACT_OK;
    struct qos_client_assignment *client = qos_priority_client(skb, 1);
    if (!client || client->expires_ns <= bpf_ktime_get_ns() ||
        !qos_priority_assignment_valid(client))
        return TC_ACT_OK;
    /* Block the original client packet before Passwall2 REDIRECT/TPROXY can
     * move it into a local proxy path. */
    if (client->flags & QOS_CLIENT_BLOCK) {
        if (qos_priority_is_internet_packet(skb, 0)) {
            qos_priority_count(skb, 7);
            return TC_ACT_SHOT;
        }
    }
    /* Exact app Flow verdicts run during packet parsing. Preserve only a leaf
     * assigned to this client's slot; unknown flows use the total/default leaf. */
    if (qos_priority_application_classid_valid(skb->priority,
            NETQMON_QOS_UPLOAD_MAJOR, client->slot)) {
        /* Keep the ingress-to-mirred packet reconciliation complete when a
         * reliable application Flow uses its own upload leaf. */
        if (ifb && *ifb && *ifb != ifindex) {
            skb->cb[0] = NETQMON_QOS_MIRRED_CB_MAGIC ^ ifindex;
            skb->cb[1] = skb->priority;
        }
        qos_priority_count(skb, 0);
        return -1;
    }
    if (!(client->flags & QOS_CLIENT_UPLOAD))
        return TC_ACT_OK;
    if (!ifb || !*ifb || *ifb == ifindex) {
        qos_priority_count(skb, 4);
        return TC_ACT_SHOT;
    }
    skb->priority = client->upload_classid;
    skb->cb[0] = NETQMON_QOS_MIRRED_CB_MAGIC ^ ifindex;
    skb->cb[1] = skb->priority;
    qos_priority_count(skb, 0);
    return -1; /* Sampling/blocking already ran. Continue to the mirred matcher. */
}

static __attribute__((noinline)) int qos_priority_egress(struct __sk_buff *skb)
{
    __u32 ifindex = skb->ifindex;
    if (!bpf_map_lookup_elem(&qos_priority_roots, &ifindex))
        return TC_ACT_OK;
    /* Capture metadata before we overwrite priority with the 51: class. This
     * lets the isolated Agent probe prove whether upload classid survived the
     * IFB return path, independently of a routed frame's rewritten source MAC. */
    qos_path_observe(skb, NETQMON_HOOK_QOS_EGRESS_PRE);
    struct qos_client_assignment *client = qos_priority_client(skb, 0);
    __u64 now = client ? bpf_ktime_get_ns() : 0;
    int client_valid = client ? qos_priority_assignment_valid(client) : 0;
    if (client && client->expires_ns > now &&
        client_valid &&
        (client->flags & QOS_CLIENT_BLOCK) &&
        qos_priority_is_internet_packet(skb, 1)) {
        qos_priority_count(skb, 7);
        return TC_ACT_SHOT;
    }
    int uploaded_after_ifb = qos_priority_upload_classid_valid(skb->priority);
    if (!uploaded_after_ifb &&
        (skb->priority >> 16) == NETQMON_QOS_DOWNLOAD_MAJOR) {
        if (client && client->expires_ns > now &&
            client_valid &&
            client->delivery_ifindex == ifindex &&
            qos_priority_application_classid_valid(skb->priority,
                NETQMON_QOS_DOWNLOAD_MAJOR, client->slot)) {
            qos_priority_count(skb, 2);
            return TC_ACT_OK;
        }
    }
    skb->priority = NETQMON_QOS_CLASSID(NETQMON_QOS_DOWNLOAD_MAJOR, NETQMON_QOS_BYPASS_MINOR);
    if (!client || !(client->flags & QOS_CLIENT_DOWNLOAD) || client->expires_ns <= now) {
        if (uploaded_after_ifb)
            qos_priority_count(skb, 6);
        qos_priority_count(skb, 3);
        return TC_ACT_OK;
    }
    if (!client_valid) {
        qos_priority_count(skb, 4);
        return TC_ACT_SHOT;
    }
    /* A moved/flooded selected destination cannot silently escape its total
     * budget through another port's bypass. Userspace must verify the new FDB
     * binding and prepare its classes before publishing that delivery path. */
    if (client->delivery_ifindex != ifindex) {
        qos_priority_count(skb, 5);
        return TC_ACT_SHOT;
    }
    skb->priority = client->download_classid;
    qos_priority_count(skb, 2);
    return TC_ACT_OK;
}

SEC("tc")
int netqmon_qos_priority_match(struct __sk_buff *skb)
{
    __u32 zero = 0, ifindex = skb->ifindex;
    if (skb->cb[0] == (NETQMON_QOS_MIRRED_CB_MAGIC ^ ifindex) &&
        skb->cb[1] == skb->priority &&
        qos_priority_upload_classid_valid(skb->priority)) {
        skb->cb[0] = 0;
        skb->cb[1] = 0;
        qos_priority_count(skb, 1);
        return -1;
    }
    __u32 *ifb = bpf_map_lookup_elem(&qos_priority_ifb, &zero);
    if (!ifb || !*ifb || *ifb == ifindex ||
        !bpf_map_lookup_elem(&qos_priority_ingress_ports, &ifindex))
        return 0;
    struct qos_client_assignment *client = qos_priority_client(skb, 1);
    if (!client || !qos_priority_assignment_valid(client) ||
        client->expires_ns <= bpf_ktime_get_ns())
        return 0;
    int application = qos_priority_application_classid_valid(skb->priority,
        NETQMON_QOS_UPLOAD_MAJOR, client->slot);
    if (!application && (!(client->flags & QOS_CLIENT_UPLOAD) ||
        skb->priority != client->upload_classid))
        return 0;
    qos_priority_count(skb, 1);
    return -1; /* Non-direct-action match; the owned mirred action redirects. */
}

SEC("tc")
int netqmon_qos_priority_ifb(struct __sk_buff *skb)
{
    qos_path_observe(skb, NETQMON_HOOK_EGRESS);
    return -1;
}
#endif
