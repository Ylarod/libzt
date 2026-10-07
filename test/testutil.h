/**
 * Shared helpers for the automated (ctest) libzt tests.
 *
 * Unlike assert(), CHECK() is not compiled out in release builds and does not
 * stop at the first failure.
 */

#ifndef LIBZT_TESTUTIL_H
#define LIBZT_TESTUTIL_H

#include <ZeroTierSockets.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static int test_checks = 0;
static int test_failures = 0;

#define CHECK(cond)                                                                                                    \
    do {                                                                                                               \
        test_checks++;                                                                                                 \
        if (! (cond)) {                                                                                                \
            test_failures++;                                                                                           \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                                            \
        }                                                                                                              \
    } while (0)

// Like CHECK() but aborts the test program, for failures that make every
// subsequent check meaningless. Uses _exit() since static destructors may
// block while the node is running (see twonode.c).
#define REQUIRE(cond)                                                                                                  \
    do {                                                                                                               \
        test_checks++;                                                                                                 \
        if (! (cond)) {                                                                                                \
            test_failures++;                                                                                           \
            fprintf(stderr, "FAIL %s:%d: %s (fatal)\n", __FILE__, __LINE__, #cond);                                    \
            fflush(stdout);                                                                                            \
            fflush(stderr);                                                                                            \
            _exit(1);                                                                                                  \
        }                                                                                                              \
    } while (0)

static long long test_now_ms()
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

// Poll until cond is true or timeout_ms has elapsed. Check cond afterwards.
#define WAIT_FOR(cond, timeout_ms)                                                                                     \
    do {                                                                                                               \
        long long _deadline = test_now_ms() + (timeout_ms);                                                            \
        while (! (cond) && test_now_ms() < _deadline) {                                                                \
            zts_util_delay(50);                                                                                        \
        }                                                                                                              \
    } while (0)

#define TEST_BEGIN(name) printf("\n*** %s\n", name)

static int test_summary(const char* program)
{
    printf("\n%s: %d checks, %d failures\n", program, test_checks, test_failures);
    return test_failures ? 1 : 0;
}

static int test_file_exists(const char* path)
{
    struct stat st;
    return stat(path, &st) == 0;
}

static int test_file_contains(const char* path, const char* needle)
{
    FILE* f = fopen(path, "rb");
    if (! f) {
        return 0;
    }
    static char buf[256 * 1024];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[n] = 0;
    return strstr(buf, needle) != NULL;
}

/**
 * zts_node_stop() returns once the node has been torn down, so the next
 * zts_init_*() call configures a new instance (previously it could still
 * reach the dying one).
 */
static void test_stop_node()
{
    long long t0 = test_now_ms();
    CHECK(zts_node_stop() == ZTS_ERR_OK);
    printf("zts_node_stop() took %lld ms\n", test_now_ms() - t0);
    // The service is gone
    CHECK(zts_node_get_id() == (uint64_t)ZTS_ERR_SERVICE);
    CHECK(zts_node_stop() == ZTS_ERR_SERVICE);
}

/**
 * Find an IPv4 address of this host on an interface the node will bind to.
 *
 * On Linux the node binds its UDP sockets to their interfaces
 * (SO_BINDTODEVICE), so packets it sends to 127.0.0.1 never reach a local
 * listener. An interface's own address is delivered locally though.
 *
 * @return 1 if found, 0 otherwise
 */
static int test_find_local_ipv4(char* dst, size_t len)
{
    struct ifaddrs* ifa_list = NULL;
    int found = 0;
    if (getifaddrs(&ifa_list) != 0) {
        return 0;
    }
    for (struct ifaddrs* ifa = ifa_list; ifa && ! found; ifa = ifa->ifa_next) {
        if (! ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET || ! (ifa->ifa_flags & IFF_UP)
            || (ifa->ifa_flags & IFF_LOOPBACK)) {
            continue;
        }
        // Mirrors the interfaces NodeService::shouldBindInterface() skips
        const char* n = ifa->ifa_name;
        if (! strncmp(n, "lo", 2) || ! strncmp(n, "zt", 2) || ! strncmp(n, "tun", 3) || ! strncmp(n, "tap", 3)
            || ! strncmp(n, "feth", 4) || ! strncmp(n, "utun", 4)) {
            continue;
        }
        const struct sockaddr_in* in4 = (const struct sockaddr_in*)ifa->ifa_addr;
        // Skip link-local (169.254/16), which the core won't use as a path
        if ((ntohl(in4->sin_addr.s_addr) >> 16) == 0xa9fe) {
            continue;
        }
        found = inet_ntop(AF_INET, &in4->sin_addr, dst, (socklen_t)len) != NULL;
    }
    freeifaddrs(ifa_list);
    return found;
}

static uint64_t test_id_from_key(const char* key)
{
    char addr[11] = { 0 };
    memcpy(addr, key, 10);
    return strtoull(addr, NULL, 16);
}

/**
 * Build a signed root set (planet) containing a single root.
 *
 * @param root_key Identity of the root (secret part is ignored)
 * @param endpoint Root endpoint in "ip/port" format
 */
static int
test_make_roots(const char* root_key, const char* endpoint, uint64_t world_id, char* roots_out, unsigned int* roots_len)
{
    // Keep only the public portion: "address:type:public"
    char pub[ZTS_ID_STR_BUF_LEN] = { 0 };
    int colons = 0;
    for (int i = 0; root_key[i] && i < ZTS_ID_STR_BUF_LEN - 1; i++) {
        if (root_key[i] == ':' && ++colons == 3) {
            break;
        }
        pub[i] = root_key[i];
    }
    char ep[ZTS_MAX_ENDPOINT_STR_LEN] = { 0 };
    strncpy(ep, endpoint, sizeof(ep) - 1);

    zts_root_set_t spec;
    memset(&spec, 0, sizeof(spec));
    spec.public_id_str[0] = pub;
    spec.endpoint_ip_str[0][0] = ep;

    char prev_key[256] = { 0 };
    char curr_key[256] = { 0 };
    unsigned int prev_key_len = sizeof(prev_key);
    unsigned int curr_key_len = sizeof(curr_key);
    *roots_len = ZTS_STORE_DATA_LEN;
    return zts_util_sign_root_set(
        roots_out,
        roots_len,
        prev_key,
        &prev_key_len,
        curr_key,
        &curr_key_len,
        world_id,
        1,
        &spec);
}

#endif   // LIBZT_TESTUTIL_H
