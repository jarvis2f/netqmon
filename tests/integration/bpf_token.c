// SPDX-License-Identifier: Apache-2.0
// Include the loader to exercise its internal preflight without requiring a
// token-capable kernel. Remaining definitions come from the same libbpf archive.
#include "../../crates/libbpf-sys/libbpf/src/libbpf.c"
#include <assert.h>

static int load_attempts;
static int memlock_attempts;
static int load_options;

int __wrap_bump_rlimit_memlock(void)
{
    memlock_attempts++;
    return 0;
}

int __wrap_bpf_prog_load(enum bpf_prog_type type, const char *name,
                        const char *license, const struct bpf_insn *insns,
                        size_t count, const struct bpf_prog_load_opts *opts)
{
    (void)type;
    (void)name;
    (void)license;
    (void)insns;
    (void)count;
    load_attempts++;
    load_options += opts != NULL;
    errno = EPERM; // Simulate a restricted token/environment denying probes.
    return -EPERM;
}

int main(void)
{
    struct bpf_object obj = { .token_fd = 42 };
    struct kern_feature_cache cache = { .token_fd = 42 };

    assert(bpf_object__probe_loading(&obj) == 0);
    assert(load_attempts == 0);
    assert(memlock_attempts == 0);

    // These capabilities exist on every token-capable kernel. A denied probe
    // must not suppress internal maps or clear expected_attach_type.
    assert(feat_supported(&cache, FEAT_PROG_NAME));
    assert(feat_supported(&cache, FEAT_GLOBAL_DATA));
    assert(feat_supported(&cache, FEAT_EXP_ATTACH_TYPE));
    assert(load_attempts == 0);

    obj.token_fd = 0;
    assert(bpf_object__probe_loading(&obj) == -EPERM);
    assert(load_attempts == 2);
    assert(memlock_attempts == 1);
    assert(load_options == 0);

    // Without a token, feature detection still obeys actual probe results.
    cache.token_fd = 0;
    assert(!feat_supported(&cache, FEAT_EXP_ATTACH_TYPE));
    assert(load_attempts == 3);

    obj.gen_loader = (void *)1;
    assert(bpf_object__probe_loading(&obj) == 0);
    assert(load_attempts == 3);
    puts("BPF token loader and feature regressions passed");
    return 0;
}
