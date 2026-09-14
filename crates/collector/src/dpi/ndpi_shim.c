/* Small version-pinned ABI boundary. No logging, packet dumping or disk I/O. */
#include <ndpi_api.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

void *nqm_ndpi_create(void) {
    struct ndpi_detection_module_struct *module = ndpi_init_detection_module(NULL);
    if (!module) return NULL;
    ndpi_set_config(module, NULL, "log.level", "0");
    /* Only our gateway/boot/flow cache is authoritative. nDPI endpoint caches
       would otherwise correlate identical private addresses across gateways. */
    const char *caches[] = {"ookla", "bittorrent", "stun", "tls_cert", "mining", "msteams", "fpc_dns", "signal"};
    for (unsigned i = 0; i < sizeof(caches)/sizeof(caches[0]); i++) {
        char setting[64];
        snprintf(setting, sizeof(setting), "lru.%s.size", caches[i]);
        ndpi_set_config(module, NULL, setting, "0");
    }
    NDPI_PROTOCOL_BITMASK all;
    NDPI_BITMASK_SET_ALL(all);
    ndpi_set_protocol_detection_bitmask2(module, &all);
    if (ndpi_finalize_initialization(module) != 0) {
        ndpi_exit_detection_module(module);
        return NULL;
    }
    return module;
}
void nqm_ndpi_destroy(void *module) { ndpi_exit_detection_module(module); }
void *nqm_ndpi_flow_create(void) { return ndpi_flow_malloc(SIZEOF_FLOW_STRUCT); }
void nqm_ndpi_flow_destroy(void *flow) { ndpi_free_flow(flow); }
/* Caller zeroes opaque flow storage through this allocator. */
void *nqm_ndpi_flow_new(void) {
    void *flow = nqm_ndpi_flow_create();
    if (flow) memset(flow, 0, SIZEOF_FLOW_STRUCT);
    return flow;
}
static int export_result(void *module, struct ndpi_flow_struct *flow, ndpi_protocol result,
                         char *master, char *application, char *hostname,
                         unsigned int capacity, double *confidence) {
    if (flow->confidence == NDPI_CONFIDENCE_MATCH_BY_PORT ||
        flow->confidence == NDPI_CONFIDENCE_MATCH_BY_IP || flow->confidence == NDPI_CONFIDENCE_UNKNOWN)
        return 0;
    if (!capacity || (!result.proto.master_protocol && !result.proto.app_protocol)) return 0;
    const char *m = result.proto.master_protocol ? ndpi_get_proto_name(module, result.proto.master_protocol) : "";
    const char *a = result.proto.app_protocol ? ndpi_get_proto_name(module, result.proto.app_protocol) : "";
    snprintf(master, capacity, "%s", m ? m : "");
    snprintf(application, capacity, "%s", a ? a : "");
    /* A full fixed-size field may contain a clipped DNS label. Never classify it
       as a complete hostname: that could turn a long attacker domain into a rule hit. */
    size_t host_length = strnlen(flow->host_server_name, sizeof(flow->host_server_name));
    if (host_length >= sizeof(flow->host_server_name) - 1) hostname[0] = 0;
    else snprintf(hostname, capacity, "%s", flow->host_server_name);
    *confidence = flow->confidence == NDPI_CONFIDENCE_DPI ? 1.0 : 0.8;
    return 1;
}
int nqm_ndpi_packet(void *module, void *state, const unsigned char *packet,
                    unsigned short length, unsigned long long timestamp,
                    char *master, char *application, char *hostname,
                    unsigned int capacity, double *confidence) {
    ndpi_protocol result = ndpi_detection_process_packet(module, state, packet, length, timestamp, NULL);
    return export_result(module, state, result, master, application, hostname, capacity, confidence);
}
int nqm_ndpi_finish(void *module, void *state, char *master, char *application,
                    char *hostname, unsigned int capacity, double *confidence) {
    unsigned char guessed = 0;
    ndpi_protocol result = ndpi_detection_giveup(module, state, &guessed);
    if (guessed) return 0;
    return export_result(module, state, result, master, application, hostname, capacity, confidence);
}
