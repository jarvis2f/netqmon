/* SPDX-License-Identifier: Apache-2.0 */
#ifndef NETQMON_BPF_H
#define NETQMON_BPF_H

#define __uint(name, value) int (*name)[value]
#define __type(name, value) value *name
#define SEC(name) __attribute__((section(name), used))
#define __always_inline inline __attribute__((always_inline))

#define BPF_MAP_TYPE_LRU_HASH 9
#define BPF_MAP_TYPE_ARRAY 2
#define BPF_MAP_TYPE_PERCPU_ARRAY 6
#define BPF_MAP_TYPE_RINGBUF 27
#define BPF_NOEXIST 1

#define TC_ACT_OK 0

#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define ETH_P_8021Q 0x8100
#define ETH_P_8021AD 0x88A8

#define IPPROTO_HOPOPTS 0
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define IPPROTO_ROUTING 43
#define IPPROTO_FRAGMENT 44
#define IPPROTO_ESP 50
#define IPPROTO_AH 51
#define IPPROTO_DSTOPTS 60

#ifndef IPPROTO_GRE
#define IPPROTO_GRE 47
#endif

#define IPV4_FRAGMENT_OFFSET_MASK 0x1FFF
#define IPV6_FRAGMENT_OFFSET_MASK 0xFFF8
#define IPV6_MAX_EXTENSION_HEADERS 6
#define MAX_VLAN_HEADERS 2
#define DNS_PORT 53
#define DNS_MAX_PAYLOAD_LENGTH 512
#define DNS_RING_BUFFER_SIZE (1 << 18)
#define DHCP_CLIENT_PORT 68
#define DHCP_SERVER_PORT 67
#define DHCP_MAX_PAYLOAD_LENGTH 576
#define DHCP_RING_BUFFER_SIZE (1 << 18)
#define MDNS_PORT 5353
#define SSDP_PORT 1900
#define DHCP6_CLIENT_PORT 546
#define DHCP6_SERVER_PORT 547
#define HTTP_PORT 80
#define DISCOVERY_MAX_PAYLOAD_LENGTH 2048
#define DISCOVERY_RING_BUFFER_SIZE (1 << 18)
#define SAMPLE_MAX_PAYLOAD_LENGTH 4096
#define SAMPLE_MAX_PACKETS_PER_DIRECTION 32
#define SAMPLE_MAX_BYTES_PER_FLOW 65536
#define SAMPLE_RING_BUFFER_SIZE (1 << 20)
#define BPF_MAP_TYPE_HASH 1

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef __u16 __be16;
typedef __u32 __be32;

/* Stable UAPI prefix through the packet data pointers used by TC programs. */
struct __sk_buff {
    __u32 len;
    __u32 pkt_type;
    __u32 mark;
    __u32 queue_mapping;
    __u32 protocol;
    __u32 vlan_present;
    __u32 vlan_tci;
    __u32 vlan_proto;
    __u32 priority;
    __u32 ingress_ifindex;
    __u32 ifindex;
    __u32 tc_index;
    __u32 cb[5];
    __u32 hash;
    __u32 tc_classid;
    __u32 data;
    __u32 data_end;
};

struct ethernet_header {
    __u8 destination[6];
    __u8 source[6];
    __be16 protocol;
} __attribute__((packed));

struct vlan_header {
    __be16 tci;
    __be16 encapsulated_protocol;
} __attribute__((packed));

struct ipv4_header {
    __u8 version_ihl;
    __u8 dscp_ecn;
    __be16 total_length;
    __be16 identification;
    __be16 fragment_offset;
    __u8 ttl;
    __u8 protocol;
    __be16 checksum;
    __be32 source;
    __be32 destination;
} __attribute__((packed));

struct ipv6_header {
    __u8 version_traffic_class;
    __u8 flow_label[3];
    __be16 payload_length;
    __u8 next_header;
    __u8 hop_limit;
    __u8 source[16];
    __u8 destination[16];
} __attribute__((packed));

struct ipv6_extension_header {
    __u8 next_header;
    __u8 length;
} __attribute__((packed));

struct ipv6_fragment_header {
    __u8 next_header;
    __u8 reserved;
    __be16 fragment_offset;
    __be32 identification;
} __attribute__((packed));

struct transport_ports {
    __be16 source;
    __be16 destination;
} __attribute__((packed));

struct udp_header {
    __be16 source;
    __be16 destination;
    __be16 length;
    __be16 checksum;
} __attribute__((packed));

struct tcp_header_prefix {
    __be16 source;
    __be16 destination;
    __be32 sequence;
    __be32 acknowledgment;
    __u8 data_offset_reserved;
    __u8 flags;
} __attribute__((packed));

/* Addresses and ports are stored in network byte order; ifindex is host order. */
struct flow_key {
    __u8 ip_version;
    __u8 protocol;
    __u8 direction;
    __u8 pad;
    __u32 ifindex;
    __u8 source_address[16];
    __u8 destination_address[16];
    __be16 source_port;
    __be16 destination_port;
};

struct flow_value {
    __u64 packets;
    __u64 bytes;
    __u64 first_seen_ns;
    __u64 last_seen_ns;
    __u64 tcp_flags;
};

struct dns_event {
    __u64 timestamp_ns;
    __u32 ifindex;
    __u32 packet_length;
    __u16 payload_length;
    __u8 ip_version;
    __u8 reserved;
    __u8 client_address[16];
    __u8 payload[DNS_MAX_PAYLOAD_LENGTH];
    __u32 reserved_tail;
};

struct dhcp_event {
    __u64 timestamp_ns;
    __u32 ifindex;
    __u32 packet_length;
    __u16 payload_length;
    __u8 reserved[2];
    __u8 payload[DHCP_MAX_PAYLOAD_LENGTH];
    __u32 reserved_tail;
};

struct discovery_event {
    __u64 timestamp_ns;
    __u32 ifindex;
    __u32 packet_length;
    __u16 captured_payload_length;
    __u8 ip_version;
    __u8 truncated;
    __u8 source_address[16];
    __u8 source_mac[6];
    __be16 source_port;
    __be16 destination_port;
    __u16 original_payload_length;
    __u8 payload[DISCOVERY_MAX_PAYLOAD_LENGTH];
};

struct sample_budget {
    __u64 first_seen_ns;
    __u64 last_seen_ns;
    __u32 bytes_seen;
    __u32 packets_seen[2];
    __u32 sampled;
};

struct sample_event {
    struct flow_key key;
    __u32 original_length;
    __u64 timestamp_ns;
    __u64 first_seen_ns;
    __u32 captured_length;
    __u32 reserved;
    __u8 payload[SAMPLE_MAX_PAYLOAD_LENGTH];
};

_Static_assert(sizeof(struct flow_key) == 44, "flow_key ABI changed");
_Static_assert(sizeof(struct flow_value) == 40, "flow_value ABI changed");
_Static_assert(sizeof(struct ipv6_header) == 40, "ipv6_header ABI changed");
_Static_assert(sizeof(struct udp_header) == 8, "udp_header ABI changed");
_Static_assert(sizeof(struct dns_event) == 552, "dns_event ABI changed");
_Static_assert(sizeof(struct dhcp_event) == 600, "dhcp_event ABI changed");
_Static_assert(sizeof(struct discovery_event) == 2096, "discovery_event ABI changed");
_Static_assert(__builtin_offsetof(struct discovery_event, captured_payload_length) == 16,
               "discovery captured length offset changed");
_Static_assert(__builtin_offsetof(struct discovery_event, truncated) == 19,
               "discovery truncation flag offset changed");
_Static_assert(__builtin_offsetof(struct discovery_event, original_payload_length) == 46,
               "discovery original length offset changed");
_Static_assert(__builtin_offsetof(struct discovery_event, payload) == 48,
               "discovery payload offset changed");
_Static_assert(sizeof(struct sample_budget) == 32, "sample_budget ABI changed");
_Static_assert(sizeof(struct sample_event) == 4168, "sample_event ABI changed");

static long (*bpf_map_update_elem)(void *map, const void *key,
                                   const void *value, __u64 flags) = (void *)2;
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static __u64 (*bpf_ktime_get_ns)(void) = (void *)5;
static long (*bpf_skb_load_bytes)(const struct __sk_buff *skb, __u32 offset,
                                  void *to, __u32 length) = (void *)26;
static void *(*bpf_ringbuf_reserve)(void *ringbuf, __u64 size,
                                    __u64 flags) = (void *)131;
static void (*bpf_ringbuf_submit)(void *data, __u64 flags) = (void *)132;
static void (*bpf_ringbuf_discard)(void *data, __u64 flags) = (void *)133;

static __always_inline __u16 netqmon_ntohs(__be16 value)
{
    return __builtin_bswap16(value);
}

#endif /* NETQMON_BPF_H */
