// SPDX-License-Identifier: Apache-2.0
#include "netqmon_bpf.h"

#ifdef NETQMON_QOS_PATH_PROBE
#include "netqmon_qos_path_probe.h"
#endif
#ifdef NETQMON_QOS_POC
#include "netqmon_qos_poc.h"
#endif
#ifdef NETQMON_QOS_PRIORITY
#include "netqmon_qos_priority.h"
#endif

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct flow_key);
    __type(value, struct flow_value);
} flow_map SEC(".maps");

/* Exact on-wire verdicts only. The Agent updates this bounded map after the
 * target kernel accepts the program and both observation hooks are attached. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_FLOW_VERDICT_ENTRIES);
    __type(key, struct flow_key);
    __type(value, struct flow_verdict);
} flow_verdict_map SEC(".maps");

/* Per-policy, per-client drop totals; LRU eviction can affect reporting only. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, struct policy_drop_key);
    __type(value, struct policy_drop_value);
} policy_drop_counters SEC(".maps");

/* Observation points used to suppress a forwarded packet at its second hook. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u8);
} observed_ifindexes SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, DNS_RING_BUFFER_SIZE);
} dns_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, DHCP_RING_BUFFER_SIZE);
} dhcp_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, DISCOVERY_RING_BUFFER_SIZE);
} discovery_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} dns_drop_count SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, SAMPLE_RING_BUFFER_SIZE);
} sample_events SEC(".maps");

/* No LRU eviction: an evicted budget could resample a still-active flow. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct flow_key);
    __type(value, struct sample_budget);
} sample_budgets SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    /* 0=sampled flows, 1=captured bytes, 2=drops, 3=dropped bytes,
     * 4=successfully submitted ring-buffer events. */
    __uint(max_entries, 5);
    __type(key, __u32);
    __type(value, __u64);
} sample_counters SEC(".maps");

volatile const __u8 sample_enabled = 1;
volatile const __u32 sample_max_packets_per_direction = 4;
volatile const __u32 sample_max_bytes_per_packet = 1024;
volatile const __u32 sample_max_bytes_per_flow = 4096;
volatile struct flow_policy_state flow_policy_state = {};

static __always_inline struct flow_verdict *active_flow_verdict(
    const struct flow_key *key)
{
    struct flow_verdict *verdict;
    __u64 now;

    verdict = bpf_map_lookup_elem(&flow_verdict_map, key);
    if (!verdict)
        return 0;
    now = bpf_ktime_get_ns();
    if (verdict->expires_monotonic_ns <= now ||
        (flow_policy_state.generation &&
         verdict->policy_generation != flow_policy_state.generation)) {
        bpf_map_delete_elem(&flow_verdict_map, key);
        return 0;
    }
    return verdict;
}

static __always_inline __u64 record_flow(struct flow_key *key,
                                         __u32 packet_length,
                                         __u8 tcp_flags);

static __always_inline void record_policy_drop(const __u8 policy_identity_hash[16],
                                                const __u8 client_mac[6],
                                                __u32 packet_length)
{
    struct policy_drop_key key = {};
    struct policy_drop_value initial = {};
    struct policy_drop_value *counter;

    __builtin_memcpy(key.policy_identity_hash, policy_identity_hash,
                     sizeof(key.policy_identity_hash));
    __builtin_memcpy(key.client_mac, client_mac, sizeof(key.client_mac));
    counter = bpf_map_lookup_elem(&policy_drop_counters, &key);
    if (!counter) {
        bpf_map_update_elem(&policy_drop_counters, &key, &initial, BPF_NOEXIST);
        counter = bpf_map_lookup_elem(&policy_drop_counters, &key);
    }
    if (counter) {
        __sync_fetch_and_add(&counter->packets, 1);
        __sync_fetch_and_add(&counter->bytes, packet_length);
    }
}

static __always_inline int apply_flow_policy(struct __sk_buff *skb,
                                             struct flow_key *key)
{
    struct flow_verdict *verdict = active_flow_verdict(key);

    if (!verdict)
        return TC_ACT_OK;

    if (verdict->verdict == NETQMON_VERDICT_SHAPE) {
#ifdef NETQMON_QOS_PRIORITY
        __u32 ifindex = skb->ifindex;
        if (bpf_map_lookup_elem(&qos_priority_roots, &ifindex)) {
            __u32 major = verdict->policy_tag >> 16;
            __u32 minor = verdict->policy_tag & 0xffff;
            if (((key->hook == NETQMON_HOOK_INGRESS &&
                  major == NETQMON_QOS_UPLOAD_MAJOR) ||
                 (key->hook == NETQMON_HOOK_EGRESS &&
                  major == NETQMON_QOS_DOWNLOAD_MAJOR)) &&
                minor >= NETQMON_QOS_APPLICATION_FIRST &&
                minor <= NETQMON_QOS_APPLICATION_LAST)
                skb->priority = verdict->policy_tag;
        } else if (key->hook == NETQMON_HOOK_EGRESS &&
                   verdict->policy_tag > 0 &&
                   verdict->policy_tag <= NETQMON_APPLICATION_MARK_MAX_TAG) {
            skb->mark = (skb->mark & ~NETQMON_APPLICATION_MARK_MASK) |
                        ((verdict->policy_tag << NETQMON_APPLICATION_MARK_SHIFT) &
                         NETQMON_APPLICATION_MARK_MASK);
        }
#else
        if (key->hook == NETQMON_HOOK_EGRESS &&
            verdict->policy_tag > 0 &&
            verdict->policy_tag <= NETQMON_APPLICATION_MARK_MAX_TAG) {
            skb->mark = (skb->mark & ~NETQMON_APPLICATION_MARK_MASK) |
                        ((verdict->policy_tag << NETQMON_APPLICATION_MARK_SHIFT) &
                         NETQMON_APPLICATION_MARK_MASK);
        }
#endif
        return TC_ACT_OK;
    }
    if (verdict->verdict != NETQMON_VERDICT_BLOCK)
        return TC_ACT_OK;

    /* Keep accounting blocked packets so the Agent can report continued flow
     * activity and refresh the bounded verdict lease. Do not run the normal
     * packet path, which can capture sample or discovery payloads. */
    record_flow(key, skb->len, 0);
    record_policy_drop(verdict->policy_identity_hash, verdict->policy_client_mac, skb->len);
    return TC_ACT_SHOT;
}

static __always_inline void record_dns_drop(void)
{
    __u32 key = 0;
    __u64 *count = bpf_map_lookup_elem(&dns_drop_count, &key);

    if (count)
        __sync_fetch_and_add(count, 1);
}

static __always_inline void sample_count(__u32 index, __u64 amount)
{
    __u64 *counter = bpf_map_lookup_elem(&sample_counters, &index);
    if (counter)
        __sync_fetch_and_add(counter, amount);
}

/* Keep this helper static so the verifier propagates the caller's skb context
   without kernel BTF; retain noinline to limit the inlined parser stack. */
static __attribute__((noinline)) int maybe_capture_sample(struct __sk_buff *skb,
                                      struct flow_key *key, __u32 network_offset,
                                      __u32 original_length)
{
    struct flow_key canonical;
    struct sample_budget initial = {};
    struct sample_budget *budget;
    struct flow_value *flow_value;
    struct sample_event *event;
    __u64 now;
    __u32 direction = 0;
    __u64 length = original_length;
    __u32 previous;
    __u32 max_bytes = sample_max_bytes_per_flow;
    __u32 max_packets = sample_max_packets_per_direction;

    if (!key)
        return 0;
    canonical = *key;
    /* A flow may use different observation interfaces in each direction. */
    canonical.ifindex = 0;
    /* Disabled means no packet payload reads or sample map operations. */
    if (!sample_enabled || !length)
        return 0;
    if (!max_bytes || max_bytes > SAMPLE_MAX_BYTES_PER_FLOW ||
        !max_packets || max_packets > SAMPLE_MAX_PACKETS_PER_DIRECTION)
        return 0;
    if (length > sample_max_bytes_per_packet)
        length = sample_max_bytes_per_packet;
    if (length > SAMPLE_MAX_PAYLOAD_LENGTH)
        length = SAMPLE_MAX_PAYLOAD_LENGTH;
    if (!length)
        return 0;

    /* Stable endpoint ordering shares one byte budget across both directions. */
#pragma unroll
    for (int i = 0; i < 16; i++) {
        if (key->source_address[i] < key->destination_address[i])
            break;
        if (key->source_address[i] > key->destination_address[i]) {
            direction = 1;
            break;
        }
        if (i == 15 && key->source_port > key->destination_port)
            direction = 1;
    }
    canonical.direction = 0;
    if (direction) {
        __builtin_memcpy(canonical.source_address, key->destination_address, 16);
        __builtin_memcpy(canonical.destination_address, key->source_address, 16);
        canonical.source_port = key->destination_port;
        canonical.destination_port = key->source_port;
    }
    now = bpf_ktime_get_ns();
    initial.first_seen_ns = now;
    initial.last_seen_ns = now;
    budget = bpf_map_lookup_elem(&sample_budgets, &canonical);
    if (!budget) {
        bpf_map_update_elem(&sample_budgets, &canonical, &initial, BPF_NOEXIST);
        budget = bpf_map_lookup_elem(&sample_budgets, &canonical);
        if (!budget) {
            sample_count(2, 1);
            sample_count(3, length);
            return 0;
        }
    }
    budget->last_seen_ns = now;
    if (budget->packets_seen[direction] >= max_packets || budget->bytes_seen >= max_bytes)
        return 0;
    previous = __sync_fetch_and_add(&budget->packets_seen[direction], 1);
    if (previous >= max_packets)
        return 0;
    previous = __sync_fetch_and_add(&budget->bytes_seen, length);
    if (previous >= max_bytes)
        return 0;
    if (length > max_bytes - previous)
        length = max_bytes - previous;
    asm volatile("" : "+r"(length));
    if (!length || length > SAMPLE_MAX_PAYLOAD_LENGTH)
        return 0;
    /* Preserve the checked range explicitly for older BPF verifiers. */
    length = ((length - 1) & (SAMPLE_MAX_PAYLOAD_LENGTH - 1)) + 1;
    /* Charge attempted samples too: queue pressure never restarts capture. */
    event = bpf_ringbuf_reserve(&sample_events, sizeof(*event), 0);
    if (!event) {
        sample_count(2, 1);
        sample_count(3, length);
        return 0;
    }
    event->key = *key;
    event->timestamp_ns = now;
    event->first_seen_ns = budget->first_seen_ns;
    flow_value = bpf_map_lookup_elem(&flow_map, key);
    event->flow_first_seen_ns = flow_value ? flow_value->first_seen_ns
                                            : budget->first_seen_ns;
    event->original_length = original_length;
    event->captured_length = length;
    event->reserved = 0;
    __u64 read_length = length;
    asm volatile("%0 += -1; %0 &= %1; %0 += 1"
                 : "+r"(read_length) : "i"(SAMPLE_MAX_PAYLOAD_LENGTH - 1) : "memory");
    if (!read_length || read_length > SAMPLE_MAX_PAYLOAD_LENGTH) {
        bpf_ringbuf_discard(event, 0);
        return 0;
    }
    if (bpf_skb_load_bytes(skb, network_offset, event->payload, read_length) != 0) {
        bpf_ringbuf_discard(event, 0);
        sample_count(2, 1);
        sample_count(3, length);
        return 0;
    }
    if (__sync_val_compare_and_swap(&budget->sampled, 0, 1) == 0)
        sample_count(0, 1);
    sample_count(1, length);
    sample_count(4, 1);
    bpf_ringbuf_submit(event, 0);
    return 0;
}

static __attribute__((noinline)) void maybe_capture_dns(struct __sk_buff *skb,
                                                        struct udp_header *udp,
                                                        const __u8 *client_address,
                                                        __u8 ip_version,
                                                        __u32 payload_offset)
{
    struct dns_event *event;
    void *data_end = (void *)(long)skb->data_end;
    __u32 available;
    __u64 capture_length;
    __u16 udp_length;
    __u8 truncated = 0;

    if ((void *)(udp + 1) > data_end || netqmon_ntohs(udp->source) != DNS_PORT)
        return;

    udp_length = netqmon_ntohs(udp->length);
    if (udp_length < sizeof(struct udp_header))
        return;
    capture_length = udp_length - sizeof(struct udp_header);
    available = (__u32)((__u8 *)data_end - (__u8 *)(udp + 1));
    if (capture_length > available) {
        capture_length = available;
        truncated = 1;
    }
    asm volatile("" : "+r"(capture_length));
    if (capture_length == 0)
        return;
    if (capture_length > DNS_MAX_PAYLOAD_LENGTH) {
        capture_length = DNS_MAX_PAYLOAD_LENGTH;
        truncated = 1;
    }
    /* Preserve 1..512 while making the range explicit to older verifiers. */
    capture_length = ((capture_length - 1) &
                      (DNS_MAX_PAYLOAD_LENGTH - 1)) + 1;

    event = bpf_ringbuf_reserve(&dns_events, sizeof(*event), 0);
    if (!event) {
        record_dns_drop();
        return;
    }

    __builtin_memset(event, 0, sizeof(*event));
    event->timestamp_ns = bpf_ktime_get_ns();
    event->ifindex = skb->ifindex;
    event->packet_length = skb->len;
    event->payload_length = capture_length;
    event->ip_version = ip_version;
    event->truncated = truncated;
    if (ip_version == 4)
        __builtin_memcpy(event->client_address, client_address, 4);
    else
        __builtin_memcpy(event->client_address, client_address, 16);

    __u64 read_length = capture_length;
    asm volatile("%0 += -1; %0 &= %1; %0 += 1"
                 : "+r"(read_length) : "i"(DNS_MAX_PAYLOAD_LENGTH - 1) : "memory");
    if (!read_length || read_length > DNS_MAX_PAYLOAD_LENGTH) {
        bpf_ringbuf_discard(event, 0);
        return;
    }
    if (bpf_skb_load_bytes(skb, payload_offset, event->payload,
                           read_length) != 0) {
        bpf_ringbuf_discard(event, 0);
        record_dns_drop();
        return;
    }
    bpf_ringbuf_submit(event, 0);
}

#define SUBMIT_DHCP_EVENT(LEN)                                                \
    do {                                                                      \
        struct dhcp_event *event =                                            \
            bpf_ringbuf_reserve(&dhcp_events, sizeof(*event), 0);             \
        if (!event)                                                           \
            return;                                                           \
        __builtin_memset(event, 0, sizeof(*event));                           \
        event->timestamp_ns = bpf_ktime_get_ns();                             \
        event->ifindex = skb->ifindex;                                        \
        event->packet_length = skb->len;                                      \
        event->payload_length = (LEN);                                        \
        __u64 read_length = (LEN);                                            \
        asm volatile("%0 += -1; %0 &= 1023; %0 += 1"                          \
                     : "+r"(read_length) : : "memory");                       \
        if (!read_length || read_length > DHCP_MAX_PAYLOAD_LENGTH) {          \
            bpf_ringbuf_discard(event, 0);                                    \
            return;                                                           \
        }                                                                     \
        if (bpf_skb_load_bytes(skb, payload_offset, event->payload,           \
                               read_length) != 0) {                           \
            bpf_ringbuf_discard(event, 0);                                    \
            return;                                                           \
        }                                                                     \
        bpf_ringbuf_submit(event, 0);                                         \
        return;                                                               \
    } while (0)

static __always_inline void maybe_capture_dhcp(struct __sk_buff *skb,
                                        struct udp_header *udp,
                                        __u32 payload_offset,
                                        __u32 available)
{
    __u16 source;
    __u16 destination;
    __u64 capture_length = available;
    asm volatile("" : "+r"(capture_length));

    if ((void *)(udp + 1) > (void *)(long)skb->data_end)
        return;
    source = netqmon_ntohs(udp->source);
    destination = netqmon_ntohs(udp->destination);
    if (!((source == DHCP_CLIENT_PORT && destination == DHCP_SERVER_PORT) ||
          (source == DHCP_SERVER_PORT && destination == DHCP_CLIENT_PORT)))
        return;
    __u32 udp_length = netqmon_ntohs(udp->length);
    if (udp_length <= sizeof(*udp)) return;
    if (capture_length > udp_length - sizeof(*udp)) capture_length = udp_length - sizeof(*udp);
    if (capture_length == 0)
        return;
    if (capture_length > DHCP_MAX_PAYLOAD_LENGTH)
        capture_length = DHCP_MAX_PAYLOAD_LENGTH;

    /* Keep option 61 and other tail options: rounding down to 240/300 bytes
       silently discarded valid DHCP options on short datagrams. */
    SUBMIT_DHCP_EVENT(capture_length);
}

#define SUBMIT_DISCOVERY_EVENT(LEN)                                           \
    do {                                                                      \
        struct discovery_event *event =                                       \
            bpf_ringbuf_reserve(&discovery_events, sizeof(*event), 0);        \
        if (!event)                                                           \
            return;                                                           \
        event->timestamp_ns = bpf_ktime_get_ns();                             \
        event->ifindex = skb->ifindex;                                        \
        event->packet_length = skb->len;                                      \
        event->original_payload_length = udp_length - sizeof(*udp);           \
        event->captured_payload_length = (LEN);                                \
        event->truncated = (LEN) < event->original_payload_length;             \
        event->ip_version = ip_version;                                       \
        event->source_port = udp->source;                                     \
        event->destination_port = udp->destination;                           \
        __builtin_memset(event->source_address, 0, sizeof(event->source_address)); \
        __builtin_memcpy(event->source_mac, source_mac, 6);                   \
        if (ip_version == 4)                                                  \
            __builtin_memcpy(event->source_address, source_address, 4);       \
        else                                                                  \
            __builtin_memcpy(event->source_address, source_address, 16);      \
        __u64 read_length = (LEN);                                            \
        asm volatile("%0 += -1; %0 &= 2047; %0 += 1"                          \
                     : "+r"(read_length) : : "memory");                       \
        if (!read_length || read_length > DISCOVERY_MAX_PAYLOAD_LENGTH) {     \
            bpf_ringbuf_discard(event, 0);                                    \
            return;                                                           \
        }                                                                     \
        if (bpf_skb_load_bytes(skb, payload_offset, event->payload,           \
                               read_length) != 0) {                           \
            bpf_ringbuf_discard(event, 0);                                    \
            return;                                                           \
        }                                                                     \
        bpf_ringbuf_submit(event, 0);                                         \
        return;                                                               \
    } while (0)

struct http_capture_ctx {
    __u32 transport_offset;
    __u32 transport_available;
    __u8 ip_version;
    __u8 source_mac[6];
    __u8 source_address[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct http_capture_ctx);
} http_ctx_map SEC(".maps");

/* The caller fills a per-CPU context so the noinline HTTP helper below
   stays within the five-argument BPF-to-BPF call limit while the inlined
   ingress path adds only a map lookup to its stack frame. */
static __always_inline struct http_capture_ctx *http_capture_context(
    __u32 transport_offset, __u32 transport_available, __u8 ip_version,
    const void *source_address, const void *source_mac)
{
    __u32 zero = 0;
    struct http_capture_ctx *ctx =
        bpf_map_lookup_elem(&http_ctx_map, &zero);
    if (!ctx)
        return 0;
    ctx->transport_offset = transport_offset;
    ctx->transport_available = transport_available;
    ctx->ip_version = ip_version;
    __builtin_memcpy(ctx->source_mac, source_mac, 6);
    __builtin_memset(ctx->source_address, 0, sizeof(ctx->source_address));
    if (ip_version == 4)
        __builtin_memcpy(ctx->source_address, source_address, 4);
    else
        __builtin_memcpy(ctx->source_address, source_address, 16);
    return ctx;
}

/* Same ring layout as SUBMIT_DISCOVERY_EVENT but for TCP captures: the
   original payload length is bounded by the packet itself because a TCP
   segment cannot be longer than the frame that carries it. The submit body
   runs inside the noinline helper below, so it reads packet metadata from
   the per-CPU context instead of caller locals. */
#define SUBMIT_DISCOVERY_TCP_EVENT(LEN, TCP)                                  \
    do {                                                                      \
        struct discovery_event *event =                                       \
            bpf_ringbuf_reserve(&discovery_events, sizeof(*event), 0);       \
        if (!event)                                                           \
            return;                                                           \
        event->timestamp_ns = bpf_ktime_get_ns();                             \
        event->ifindex = skb->ifindex;                                        \
        event->packet_length = skb->len;                                      \
        event->original_payload_length = available;                           \
        event->captured_payload_length = (LEN);                               \
        event->truncated = (LEN) < event->original_payload_length;           \
        event->ip_version = ctx->ip_version;                                   \
        event->source_port = (TCP)->source;                                   \
        event->destination_port = (TCP)->destination;                         \
        __builtin_memset(event->source_address, 0, sizeof(event->source_address)); \
        __builtin_memcpy(event->source_mac, ctx->source_mac, 6);             \
        if (ctx->ip_version == 4)                                             \
            __builtin_memcpy(event->source_address, ctx->source_address, 4); \
        else                                                                  \
            __builtin_memcpy(event->source_address, ctx->source_address, 16);\
        __u64 read_length = (LEN);                                            \
        asm volatile("%0 += -1; %0 &= 2047; %0 += 1"                          \
                     : "+r"(read_length) : : "memory");                       \
        if (!read_length || read_length > DISCOVERY_MAX_PAYLOAD_LENGTH) {     \
            bpf_ringbuf_discard(event, 0);                                    \
            return;                                                           \
        }                                                                     \
        if (bpf_skb_load_bytes(skb, payload_offset, event->payload,           \
                               read_length) != 0) {                           \
            bpf_ringbuf_discard(event, 0);                                    \
            return;                                                           \
        }                                                                     \
        bpf_ringbuf_submit(event, 0);                                         \
        return;                                                               \
    } while (0)

static __always_inline void maybe_capture_discovery(struct __sk_buff *skb,
                                       struct udp_header *udp,
                                       __u32 payload_offset, __u32 available,
                                       const __u8 *source_address,
                                       const __u8 *source_mac, __u8 ip_version)
{
    __u16 source;
    __u16 destination;
    __u64 capture_length = available;
    /* Keep a 64-bit range check with ALU32 enabled, including older verifiers. */
    asm volatile("" : "+r"(capture_length));

    if ((void *)(udp + 1) > (void *)(long)skb->data_end)
        return;
    source = netqmon_ntohs(udp->source);
    destination = netqmon_ntohs(udp->destination);
    if (!(source == MDNS_PORT || destination == MDNS_PORT ||
          source == SSDP_PORT || destination == SSDP_PORT ||
          (source == DHCP6_CLIENT_PORT && destination == DHCP6_SERVER_PORT)))
        return;
    __u32 udp_length = netqmon_ntohs(udp->length);
    if (udp_length <= sizeof(*udp))
        return;
    if (capture_length > udp_length - sizeof(*udp))
        capture_length = udp_length - sizeof(*udp);
    if (capture_length == 0)
        return;
    if (capture_length > DISCOVERY_MAX_PAYLOAD_LENGTH)
        capture_length = DISCOVERY_MAX_PAYLOAD_LENGTH;
    /* Preserve exact datagram length: rounding down breaks DNS record parsing. */
    SUBMIT_DISCOVERY_EVENT(capture_length);
}

/* Capture the first TCP segment of plaintext HTTP requests so the agent
   can lift the User-Agent header as device evidence. Filtered to port 80
   and to well-known request-method prefixes to keep the ring buffer quiet;
   TLS on port 80 and every other binary fails the prefix check. Marked
   noinline like maybe_capture_sample so the inlined ingress stack stays
   within the 512-byte verifier limit. */
__attribute__((noinline)) static void maybe_capture_http_discovery(
    struct __sk_buff *skb, struct tcp_header_prefix *tcp,
    struct http_capture_ctx *ctx)
{
    __u32 data_offset;
    __u32 payload_offset;
    __u32 available;
    __u8 method[4];
    __u32 capture_length;

    if ((void *)(tcp + 1) > (void *)(long)skb->data_end)
        return;
    if (netqmon_ntohs(tcp->destination) != HTTP_PORT)
        return;
    data_offset = ((__u32)tcp->data_offset_reserved) >> 2;
    if (data_offset < sizeof(struct tcp_header_prefix))
        return;
    if (ctx->transport_available <= data_offset)
        return;
    available = ctx->transport_available - data_offset;
    payload_offset = ctx->transport_offset + data_offset;
    if (available < sizeof(method))
        return;
    if (bpf_skb_load_bytes(skb, payload_offset, method, sizeof(method)) != 0)
        return;
    if (!(('G' == method[0] && 'E' == method[1] && 'T' == method[2] &&
           ' ' == method[3]) ||
          ('P' == method[0] && 'O' == method[1] && 'S' == method[2] &&
           'T' == method[3]) ||
          ('H' == method[0] && 'E' == method[1] && 'A' == method[2] &&
           'D' == method[3]) ||
          ('P' == method[0] && 'U' == method[1] && 'T' == method[2] &&
           ' ' == method[3]) ||
          ('P' == method[0] && 'A' == method[1] && 'T' == method[2] &&
           'C' == method[3]) ||
          ('D' == method[0] && 'E' == method[1] && 'L' == method[2] &&
           'E' == method[3]) ||
          ('O' == method[0] && 'P' == method[1] && 'T' == method[2] &&
           'I' == method[3]) ||
          ('C' == method[0] && 'O' == method[1] && 'N' == method[2] &&
           'N' == method[3])))
        return;
    capture_length = available;
    if (capture_length > DISCOVERY_MAX_PAYLOAD_LENGTH)
        capture_length = DISCOVERY_MAX_PAYLOAD_LENGTH;
    SUBMIT_DISCOVERY_TCP_EVENT(capture_length, tcp);
}

static __always_inline __u64 update_flow_value(struct flow_value *value,
                                        __u32 packet_length, __u64 now,
                                        __u8 tcp_flags)
{
    __u64 previous = __sync_fetch_and_add(&value->packets, 1);
    __sync_fetch_and_add(&value->bytes, packet_length);
    __sync_lock_test_and_set(&value->last_seen_ns, now);
    if (tcp_flags)
        __sync_fetch_and_or(&value->tcp_flags, tcp_flags);
    return previous + 1;
}

static __always_inline __u64 record_flow(struct flow_key *key, __u32 packet_length,
                                  __u8 tcp_flags)
{
    __u64 now = bpf_ktime_get_ns();
    struct flow_value *existing = bpf_map_lookup_elem(&flow_map, key);
    struct flow_value initial = {
        .packets = 1,
        .bytes = packet_length,
        .first_seen_ns = now,
        .last_seen_ns = now,
        .tcp_flags = tcp_flags,
    };

    if (existing) {
        return update_flow_value(existing, packet_length, now, tcp_flags);
    }

    if (bpf_map_update_elem(&flow_map, key, &initial, BPF_NOEXIST) != 0) {
        existing = bpf_map_lookup_elem(&flow_map, key);
        if (existing)
            return update_flow_value(existing, packet_length, now, tcp_flags);
    }
    return 1;
}

static __always_inline __u8 read_tcp_flags(__u8 *cursor, void *data_end)
{
    struct tcp_header_prefix *tcp = (void *)cursor;

    if ((void *)(tcp + 1) > data_end)
        return 0;
    return tcp->flags;
}

static __always_inline int parse_ipv4(struct __sk_buff *skb, __u8 *cursor,
                                void *data_end, __u32 ifindex,
                                __u32 packet_length, __u32 network_offset,
                                __u8 hook,
                                const __u8 *source_mac, int policy_only)
{
    struct flow_key key = {};
    struct ipv4_header *ipv4 = (void *)cursor;
    struct transport_ports *ports;
    __u16 fragment_offset;
    __u8 tcp_flags = 0;
    __u8 ihl;

    if ((void *)(ipv4 + 1) > data_end)
        return TC_ACT_OK;
    if ((ipv4->version_ihl >> 4) != 4)
        return TC_ACT_OK;

    ihl = (ipv4->version_ihl & 0x0F) * 4;
    if (ihl < sizeof(*ipv4) || cursor + ihl > (__u8 *)data_end)
        return TC_ACT_OK;
    if (ipv4->protocol != IPPROTO_TCP && ipv4->protocol != IPPROTO_UDP &&
        ipv4->protocol != IPPROTO_ESP && ipv4->protocol != IPPROTO_GRE)
        return TC_ACT_OK;

    key.ip_version = 4;
    key.protocol = ipv4->protocol;
    key.hook = hook;
    key.ifindex = ifindex;
    __builtin_memcpy(key.source_address, &ipv4->source, sizeof(ipv4->source));
    __builtin_memcpy(key.destination_address, &ipv4->destination,
                     sizeof(ipv4->destination));

    fragment_offset = netqmon_ntohs(ipv4->fragment_offset);
    if ((fragment_offset & IPV4_FRAGMENT_OFFSET_MASK) == 0) {
        if (key.protocol == IPPROTO_ESP || key.protocol == IPPROTO_GRE) {
            if (policy_only)
                return TC_ACT_OK;
            __u64 flow_packets = record_flow(&key, packet_length, 0);
            if (sample_enabled &&
                flow_packets <= sample_max_packets_per_direction)
                maybe_capture_sample(skb, &key, network_offset,
                                     netqmon_ntohs(ipv4->total_length));
            return TC_ACT_OK;
        }
        ports = (void *)(cursor + ihl);
        if ((void *)(ports + 1) > data_end)
            return TC_ACT_OK;
        key.source_port = ports->source;
        key.destination_port = ports->destination;
        if (flow_policy_state.enabled) {
            int action = apply_flow_policy(skb, &key);
            if (action != TC_ACT_OK) {
                return action;
            }
        }
        if (policy_only)
            return TC_ACT_OK;
        if (key.protocol == IPPROTO_TCP) {
            tcp_flags = read_tcp_flags(cursor + ihl, data_end);
            if (netqmon_ntohs(key.destination_port) == HTTP_PORT) {
                struct http_capture_ctx *http_ctx = http_capture_context(
                    network_offset + ihl,
                    packet_length > network_offset + ihl
                        ? packet_length - network_offset - ihl
                        : 0,
                    4, &ipv4->source, source_mac);
                if (http_ctx)
                    maybe_capture_http_discovery(
                        skb, (struct tcp_header_prefix *)(cursor + ihl),
                        http_ctx);
            }
        } else {
            __u32 payload_offset = network_offset + ihl +
                                   sizeof(struct udp_header);
            __u32 available = packet_length > payload_offset
                                  ? packet_length - payload_offset
                                  : 0;

            maybe_capture_dns(skb, (struct udp_header *)(cursor + ihl),
                              (__u8 *)&ipv4->destination, 4,
                              network_offset + ihl + sizeof(struct udp_header));
            maybe_capture_dhcp(skb, (struct udp_header *)(cursor + ihl),
                               payload_offset, available);
            maybe_capture_discovery(skb, (struct udp_header *)(cursor + ihl),
                                    payload_offset, available,
                                    (__u8 *)&ipv4->source, source_mac, 4);
        }
    }

    if (policy_only)
        return TC_ACT_OK;

    __u64 flow_packets = record_flow(&key, packet_length, tcp_flags);
    if (sample_enabled &&
        flow_packets <= sample_max_packets_per_direction &&
        (fragment_offset & IPV4_FRAGMENT_OFFSET_MASK) == 0 &&
        netqmon_ntohs(ipv4->total_length) >= ihl)
        maybe_capture_sample(skb, &key, network_offset, netqmon_ntohs(ipv4->total_length));
    return TC_ACT_OK;
}

static __always_inline int parse_ipv6(struct __sk_buff *skb, __u8 *cursor,
                                void *data_end, __u32 ifindex,
                                __u32 packet_length, __u32 network_offset,
                                __u8 hook,
                                const __u8 *source_mac, int policy_only)
{
    struct flow_key key = {};
    struct ipv6_header *ipv6 = (void *)cursor;
    __u8 can_parse_transport = 1;
    __u8 next_header;
    __u32 transport_offset;

    if ((void *)(ipv6 + 1) > data_end)
        return TC_ACT_OK;
    if ((ipv6->version_traffic_class >> 4) != 6)
        return TC_ACT_OK;

    key.ip_version = 6;
    key.hook = hook;
    key.ifindex = ifindex;
    __builtin_memcpy(key.source_address, ipv6->source, sizeof(ipv6->source));
    __builtin_memcpy(key.destination_address, ipv6->destination,
                     sizeof(ipv6->destination));

    cursor += sizeof(*ipv6);
    transport_offset = network_offset + sizeof(*ipv6);
    next_header = ipv6->next_header;

#pragma unroll
    for (int index = 0; index < IPV6_MAX_EXTENSION_HEADERS; index++) {
        struct ipv6_extension_header *extension;
        __u32 extension_length;

        if (next_header == IPPROTO_TCP || next_header == IPPROTO_UDP) {
            struct transport_ports *ports = (void *)cursor;

            key.protocol = next_header;
            if ((void *)(ports + 1) <= data_end) {
                key.source_port = ports->source;
                key.destination_port = ports->destination;
                if (flow_policy_state.enabled) {
                    int action = apply_flow_policy(skb, &key);
                    if (action != TC_ACT_OK) {
                        return action;
                    }
                }
                if (policy_only)
                    return TC_ACT_OK;
            }
            if (next_header == IPPROTO_UDP) {
                __u32 payload_offset = transport_offset +
                                       sizeof(struct udp_header);
                __u32 available = packet_length > payload_offset
                                      ? packet_length - payload_offset
                                      : 0;

                maybe_capture_dns(skb, (struct udp_header *)cursor,
                                  ipv6->destination, 6,
                                  transport_offset + sizeof(struct udp_header));
                maybe_capture_discovery(skb, (struct udp_header *)cursor,
                                        payload_offset, available, ipv6->source,
                                        source_mac, 6);
            } else if (next_header == IPPROTO_TCP) {
                if (netqmon_ntohs(key.destination_port) == HTTP_PORT) {
                    struct http_capture_ctx *http_ctx = http_capture_context(
                        transport_offset,
                        packet_length > transport_offset
                            ? packet_length - transport_offset
                            : 0,
                        6, ipv6->source, source_mac);
                    if (http_ctx)
                        maybe_capture_http_discovery(
                            skb, (struct tcp_header_prefix *)cursor, http_ctx);
                }
            }
            __u64 flow_packets = record_flow(
                &key, packet_length,
                next_header == IPPROTO_TCP ? read_tcp_flags(cursor, data_end) : 0);
            if (sample_enabled &&
                flow_packets <= sample_max_packets_per_direction)
                maybe_capture_sample(
                    skb, &key, network_offset,
                    sizeof(*ipv6) + netqmon_ntohs(ipv6->payload_length));
            return TC_ACT_OK;
        }

        extension = (void *)cursor;
        if ((void *)(extension + 1) > data_end)
            break;

        if (next_header == IPPROTO_FRAGMENT) {
            struct ipv6_fragment_header *fragment = (void *)cursor;

            if ((void *)(fragment + 1) > data_end)
                break;
            next_header = fragment->next_header;
            cursor += sizeof(*fragment);
            transport_offset += sizeof(*fragment);
            if ((netqmon_ntohs(fragment->fragment_offset) &
                 IPV6_FRAGMENT_OFFSET_MASK) != 0) {
                can_parse_transport = 0;
                break;
            }
            continue;
        }

        if (next_header == IPPROTO_HOPOPTS ||
            next_header == IPPROTO_ROUTING ||
            next_header == IPPROTO_DSTOPTS) {
            extension_length = ((__u32)extension->length + 1) * 8;
        } else if (next_header == IPPROTO_AH) {
            extension_length = ((__u32)extension->length + 2) * 4;
        } else {
            break;
        }

        if (cursor + extension_length > (__u8 *)data_end)
            break;
        next_header = extension->next_header;
        cursor += extension_length;
        transport_offset += extension_length;
    }

    if (policy_only)
        return TC_ACT_OK;

    key.protocol = next_header;
    if (can_parse_transport &&
        (next_header == IPPROTO_TCP || next_header == IPPROTO_UDP)) {
        struct transport_ports *ports = (void *)cursor;

        if ((void *)(ports + 1) <= data_end) {
            key.source_port = ports->source;
            key.destination_port = ports->destination;
        }
        if (next_header == IPPROTO_UDP)
            maybe_capture_dns(skb, (struct udp_header *)cursor,
                              ipv6->destination, 6,
                              transport_offset + sizeof(struct udp_header));
    }
    record_flow(&key, packet_length,
                can_parse_transport && next_header == IPPROTO_TCP
                    ? read_tcp_flags(cursor, data_end)
                    : 0);
    return TC_ACT_OK;
}

static __always_inline int parse_packet(struct __sk_buff *skb, void *data,
                                         void *data_end, __u32 ifindex,
                                         __u32 packet_length, __u8 hook,
                                         int policy_only)
{
    struct ethernet_header *ethernet = data;
    __u8 *cursor;
    __u32 cursor_offset;
    __u16 ethernet_protocol;

    if ((void *)(ethernet + 1) > data_end)
        return TC_ACT_OK;

    cursor = data + sizeof(*ethernet);
    cursor_offset = sizeof(*ethernet);
    ethernet_protocol = netqmon_ntohs(ethernet->protocol);

#pragma unroll
    for (int index = 0; index < MAX_VLAN_HEADERS; index++) {
        struct vlan_header *vlan;

        if (ethernet_protocol != ETH_P_8021Q &&
            ethernet_protocol != ETH_P_8021AD)
            break;
        vlan = (void *)cursor;
        if ((void *)(vlan + 1) > data_end)
            return TC_ACT_OK;
        ethernet_protocol = netqmon_ntohs(vlan->encapsulated_protocol);
        cursor += sizeof(*vlan);
        cursor_offset += sizeof(*vlan);
    }

    if (ethernet_protocol == ETH_P_8021Q ||
        ethernet_protocol == ETH_P_8021AD)
        return TC_ACT_OK;

    if (ethernet_protocol == ETH_P_IP)
        return parse_ipv4(skb, cursor, data_end, ifindex, packet_length,
                          cursor_offset, hook, ethernet->source, policy_only);
    if (ethernet_protocol == ETH_P_IPV6)
        return parse_ipv6(skb, cursor, data_end, ifindex, packet_length,
                          cursor_offset, hook, ethernet->source, policy_only);
    return TC_ACT_OK;
}

#ifdef NETQMON_QOS_PRIORITY
/* A global BPF subprogram is verified independently of all IPv4/IPv6 parser
 * branches. Inlining this continuation multiplies those states through the
 * map-in-map classifier and path observer, exceeding the verifier complexity
 * bound on the supported 6.1 test kernel. Keep the ordering explicit: policy
 * verdict first, priority only for accepted packets, then one observation. */
__attribute__((noinline)) int qos_priority_finish_egress(struct __sk_buff *skb, int action)
{
    if (action == TC_ACT_OK) {
#ifdef NETQMON_QOS_POC
        qos_poc_egress(skb);
#endif
        action = qos_priority_egress(skb);
    }
    qos_path_observe(skb, NETQMON_HOOK_EGRESS);
    return action;
}
#endif

SEC("tc")
int netqmon_ingress(struct __sk_buff *skb)
{
#ifdef NETQMON_QOS_PATH_PROBE
    qos_path_observe(skb, NETQMON_HOOK_INGRESS);
#endif
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    int action = parse_packet(skb, data, data_end, skb->ifindex, skb->len,
                              NETQMON_HOOK_INGRESS, 0);
#ifdef NETQMON_QOS_PRIORITY
    if (action == TC_ACT_OK) {
        int priority_action = qos_priority_ingress(skb);
        if (priority_action != TC_ACT_OK)
            return priority_action;
    }
#endif
#ifdef NETQMON_QOS_POC
    if (action == TC_ACT_OK)
        return qos_poc_ingress(skb);
#endif
    return action;
}

#ifdef NETQMON_QOS_PRIORITY
__attribute__((noinline))
int netqmon_policy_account_egress(struct __sk_buff *skb)
#else
SEC("tc")
int netqmon_egress(struct __sk_buff *skb)
#endif
{
#if defined(NETQMON_QOS_POC) && !defined(NETQMON_QOS_PRIORITY)
    /* Classification must run even if accounting is suppressed at this hook. */
    qos_poc_egress(skb);
#endif
#if defined(NETQMON_QOS_PATH_PROBE) && !defined(NETQMON_QOS_PRIORITY)
    qos_path_observe(skb, NETQMON_HOOK_EGRESS);
#endif
    __u32 ingress_ifindex = skb->ingress_ifindex;
    int policy_only = 0;

    /* If this packet already crossed a selected ingress hook, accounting it
     * again at egress would double count selected-to-selected paths. Still
     * inspect the exact flow key when policy execution is active. */
    if (ingress_ifindex &&
        bpf_map_lookup_elem(&observed_ifindexes, &ingress_ifindex)) {
        if (!flow_policy_state.enabled) {
            return TC_ACT_OK;
        }
        policy_only = 1;
    }

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    int action = parse_packet(skb, data, data_end, skb->ifindex, skb->len,
                              NETQMON_HOOK_EGRESS, policy_only);
    return action;
}

#ifdef NETQMON_QOS_PRIORITY
SEC("tc")
int netqmon_egress(struct __sk_buff *skb)
{
    int action = netqmon_policy_account_egress(skb);
    return qos_priority_finish_egress(skb, action);
}
#endif

SEC("tc")
int netqmon_attach_probe(struct __sk_buff *skb)
{
    (void)skb;
    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
