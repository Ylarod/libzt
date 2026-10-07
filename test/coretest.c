/**
 * Offline integration test for libzt and the ZeroTier core.
 *
 * Needs no Internet access and no network controller:
 *
 *  - Root sets are generated and signed locally with zts_util_sign_root_set()
 *    so the public planet is never contacted.
 *  - A plain UDP socket stands in for a root to capture the node's HELLO
 *    packets.
 *  - A node that is its own root is considered online by the core, which lets
 *    us exercise ad-hoc (controller-less) networks end to end.
 *
 * Usage: coretest [work_dir]
 */

#include "testutil.h"
#include "version.h"

#include <ZeroTierSockets.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdatomic.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

// Ad-hoc networks only allow TCP/UDP to ports within the range encoded in the
// ID
#define ADHOC_A_START 9000
#define ADHOC_A_END   9100
#define ADHOC_B_START 9200
#define ADHOC_B_END   9300

#define TEST_WORLD_ID 0x0000c0ffee15600dULL

static char work_dir[512] = { 0 };

//----------------------------------------------------------------------------//
// Events                                                                     //
//----------------------------------------------------------------------------//

static atomic_int ev_node_up;
static atomic_int ev_node_online;
static atomic_int ev_net_ready_ip6;
static atomic_int ev_addr_added_ip6;
static zts_node_info_t node_up_info;
static zts_net_info_t net_ready_info;

static void on_zts_event(void* ptr)
{
    zts_event_msg_t* msg = (zts_event_msg_t*)ptr;
    switch (msg->event_code) {
        case ZTS_EVENT_NODE_UP:
            memcpy(&node_up_info, msg->node, sizeof(node_up_info));
            atomic_store(&ev_node_up, 1);
            break;
        case ZTS_EVENT_NODE_ONLINE:
            atomic_store(&ev_node_online, 1);
            break;
        case ZTS_EVENT_NETWORK_READY_IP6:
            memcpy(&net_ready_info, msg->network, sizeof(net_ready_info));
            atomic_store(&ev_net_ready_ip6, 1);
            break;
        case ZTS_EVENT_ADDR_ADDED_IP6:
            atomic_store(&ev_addr_added_ip6, 1);
            break;
        default:
            break;
    }
}

static void reset_events()
{
    atomic_store(&ev_node_up, 0);
    atomic_store(&ev_node_online, 0);
    atomic_store(&ev_net_ready_ip6, 0);
    atomic_store(&ev_addr_added_ip6, 0);
    memset(&node_up_info, 0, sizeof(node_up_info));
    memset(&net_ready_info, 0, sizeof(net_ready_info));
}

//----------------------------------------------------------------------------//
// Helpers                                                                    //
//----------------------------------------------------------------------------//

static void node_path(char* dst, size_t len, const char* name)
{ snprintf(dst, len, "%s/%s", work_dir, name); }

static void start_node(
    const char* storage,
    const char* key,
    const char* roots,
    unsigned int roots_len)
{
    reset_events();
    if (storage) {
        REQUIRE(zts_init_from_storage(storage) == ZTS_ERR_OK);
    }
    if (key) {
        REQUIRE(zts_init_from_memory(key, ZTS_ID_STR_BUF_LEN) == ZTS_ERR_OK);
    }
    REQUIRE(zts_init_set_event_handler(&on_zts_event) == ZTS_ERR_OK);
    REQUIRE(zts_init_set_roots(roots, roots_len) == ZTS_ERR_OK);
    // Keep the test hermetic: no uPnP/NAT-PMP traffic
    REQUIRE(zts_init_allow_port_mapping(0) == ZTS_ERR_OK);
    REQUIRE(zts_node_start() == ZTS_ERR_OK);
    WAIT_FOR(atomic_load(&ev_node_up), 15000);
    REQUIRE(atomic_load(&ev_node_up));
}

static int ip6_equal(
    const struct zts_sockaddr_storage* a,
    const struct zts_sockaddr_storage* b)
{
    const struct zts_sockaddr_in6* a6 = (const struct zts_sockaddr_in6*)a;
    const struct zts_sockaddr_in6* b6 = (const struct zts_sockaddr_in6*)b;
    return a6->sin6_family == ZTS_AF_INET6 && b6->sin6_family == ZTS_AF_INET6
           && memcmp(&a6->sin6_addr, &b6->sin6_addr, sizeof(a6->sin6_addr))
                  == 0;
}

static uint64_t read_addr40(const uint8_t* p)
{
    uint64_t a = 0;
    for (int i = 0; i < 5; i++) {
        a = (a << 8) | p[i];
    }
    return a;
}

static uint64_t read_u64(const uint8_t* p)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) {
        v = (v << 8) | p[i];
    }
    return v;
}

//----------------------------------------------------------------------------//
// Tests                                                                      //
//----------------------------------------------------------------------------//

static void test_pre_start()
{
    TEST_BEGIN("test_pre_start");

    // Previously dereferenced the (not yet created) core node and crashed
    CHECK(zts_init_set_low_bandwidth_mode(1) == ZTS_ERR_OK);
    CHECK(zts_init_set_low_bandwidth_mode(0) == ZTS_ERR_OK);
    CHECK(zts_init_set_encrypted_hello(1) == ZTS_ERR_OK);
    CHECK(zts_init_set_encrypted_hello(0) == ZTS_ERR_OK);

    // Queries that require a running node
    CHECK(zts_node_is_online() == 0);
    CHECK(zts_node_get_id() == (uint64_t)ZTS_ERR_SERVICE);
    CHECK(zts_net_join(0x1234) == ZTS_ERR_SERVICE);
    CHECK(zts_net_transport_is_ready(0x1234) == ZTS_ERR_SERVICE);
    CHECK(zts_bsd_socket(ZTS_AF_INET6, ZTS_SOCK_STREAM, 0) == ZTS_ERR_SERVICE);
    CHECK(zts_node_stop() == ZTS_ERR_SERVICE);

    // Invalid root sets are rejected
    char buf[16] = { 0 };
    CHECK(zts_init_set_roots(NULL, 16) == ZTS_ERR_ARG);
    CHECK(zts_init_set_roots(buf, 0) == ZTS_ERR_ARG);
    CHECK(zts_init_set_roots(buf, ZTS_STORE_DATA_LEN + 1) == ZTS_ERR_ARG);
}

static void test_identity_and_addressing()
{
    TEST_BEGIN("test_identity_and_addressing");

    char key[ZTS_ID_STR_BUF_LEN] = { 0 };
    unsigned int key_len = ZTS_ID_STR_BUF_LEN;
    CHECK(zts_id_new(key, &key_len) == ZTS_ERR_OK);
    CHECK(key_len > 0 && key_len < ZTS_ID_STR_BUF_LEN);
    CHECK(zts_id_pair_is_valid(key, ZTS_ID_STR_BUF_LEN) == 1);
    // "address:type:public:secret"
    CHECK(key[10] == ':' && key[11] == '0' && key[12] == ':');

    // Two fresh identities never collide
    char key2[ZTS_ID_STR_BUF_LEN] = { 0 };
    unsigned int key2_len = ZTS_ID_STR_BUF_LEN;
    CHECK(zts_id_new(key2, &key2_len) == ZTS_ERR_OK);
    CHECK(strcmp(key, key2) != 0);

    // Address derivation (known answers)
    uint64_t net_id = zts_net_compute_adhoc_id(ADHOC_A_START, ADHOC_A_END);
    CHECK(net_id == 0xff2328238c000000ULL);
    char ipstr[ZTS_IP_MAX_STR_LEN] = { 0 };
    CHECK(
        zts_addr_compute_6plane_str(
            0xff07d00bb8000000ULL,
            0x75f3543094ULL,
            ipstr,
            sizeof(ipstr))
        == ZTS_ERR_OK);
    CHECK(! strcmp(ipstr, "FC47:7D0:B75:F354:3094::1"));
    CHECK(
        zts_addr_compute_rfc4193_str(
            0xff07d00bb8000000ULL,
            0x75f3543094ULL,
            ipstr,
            sizeof(ipstr))
        == ZTS_ERR_OK);
    CHECK(! strcmp(ipstr, "FDFF:7D0:BB8:0:99:9375:F354:3094"));

    // Larger buffers are fine (used to require exactly ZTS_IP_MAX_STR_LEN),
    // smaller ones are rejected
    char big[128];
    memset(big, 'x', sizeof(big));
    CHECK(zts_addr_compute_6plane_str(0xff07d00bb8000000ULL, 0x75f3543094ULL, big, sizeof(big)) == ZTS_ERR_OK);
    CHECK(! strcmp(big, "FC47:7D0:B75:F354:3094::1"));
    CHECK(
        zts_addr_compute_rfc4193_str(0xff07d00bb8000000ULL, 0x75f3543094ULL, ipstr, ZTS_IP_MAX_STR_LEN - 1)
        == ZTS_ERR_ARG);
}

static void test_sign_root_set()
{
    TEST_BEGIN("test_sign_root_set");

    char key[ZTS_ID_STR_BUF_LEN] = { 0 };
    unsigned int key_len = ZTS_ID_STR_BUF_LEN;
    REQUIRE(zts_id_new(key, &key_len) == ZTS_ERR_OK);

    char roots[ZTS_STORE_DATA_LEN] = { 0 };
    unsigned int roots_len = 0;
    char prev_key[256] = { 0 };
    char curr_key[256] = { 0 };
    unsigned int prev_len = sizeof(prev_key);
    unsigned int curr_len = sizeof(curr_key);

    // Argument checks
    CHECK(
        zts_util_sign_root_set(
            roots,
            &roots_len,
            prev_key,
            &prev_len,
            curr_key,
            &curr_len,
            1,
            1,
            NULL)
        == ZTS_ERR_ARG);

    // Signs with the core's ECC implementation and round-trips the result
    // through World serialization internally
    CHECK(
        test_make_roots(key, "127.0.0.1/9993", TEST_WORLD_ID, roots, &roots_len)
        == ZTS_ERR_OK);
    CHECK(roots_len > 64 && roots_len <= ZTS_STORE_DATA_LEN);
    // First byte of a serialized World is its type (1 == planet), followed by
    // the 64-bit world ID
    CHECK((uint8_t)roots[0] == 1);
    CHECK(read_u64((const uint8_t*)roots + 1) == TEST_WORLD_ID);

    zts_root_set_t spec;
    memset(&spec, 0, sizeof(spec));
    char pub[ZTS_ID_STR_BUF_LEN] = { 0 };
    memcpy(
        pub,
        key,
        10 + 3 + 128);   // "address:0:" + 64 byte public key in hex
    char ep[] = "10.0.0.1/9993";
    spec.public_id_str[0] = pub;
    spec.endpoint_ip_str[0][0] = ep;
    roots_len = sizeof(roots);
    CHECK(
        zts_util_sign_root_set(
            roots,
            &roots_len,
            prev_key,
            &prev_len,
            curr_key,
            &curr_len,
            2,
            2,
            &spec)
        == ZTS_ERR_OK);
    // Generated signing key pairs are returned to the caller (public + secret)
    CHECK(prev_len == 128);
    CHECK(curr_len == 128);
}

/**
 * Start a node whose only root is a local UDP socket and verify that the node
 * really uses the custom root set by inspecting the HELLO it sends.
 *
 * With encrypted HELLO (new in 1.16) everything after the packet header is
 * encrypted to the root's public key, so only the header can be checked.
 */
static ssize_t plain_hello_len = 0;

static uint64_t test_custom_roots_hello(int encrypted_hello)
{
    TEST_BEGIN(encrypted_hello ? "test_custom_roots_hello (encrypted)" : "test_custom_roots_hello");

    char local_ip[INET_ADDRSTRLEN] = { 0 };
    int have_local_ip = test_find_local_ipv4(local_ip, sizeof(local_ip));
    if (! have_local_ip) {
        // Still start the node, but HELLO capture is impossible
        printf("SKIP: no usable IPv4 interface, not capturing HELLO\n");
        snprintf(local_ip, sizeof(local_ip), "192.0.2.1");
    }

    int fake_root = socket(AF_INET, SOCK_DGRAM, 0);
    REQUIRE(fake_root >= 0);
    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_ANY);
    sin.sin_port = 0;
    REQUIRE(bind(fake_root, (struct sockaddr*)&sin, sizeof(sin)) == 0);
    socklen_t slen = sizeof(sin);
    REQUIRE(getsockname(fake_root, (struct sockaddr*)&sin, &slen) == 0);
    struct timeval tv = { 1, 0 };
    setsockopt(fake_root, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    char root_key[ZTS_ID_STR_BUF_LEN] = { 0 };
    unsigned int root_key_len = ZTS_ID_STR_BUF_LEN;
    REQUIRE(zts_id_new(root_key, &root_key_len) == ZTS_ERR_OK);
    uint64_t root_id = test_id_from_key(root_key);

    char endpoint[64] = { 0 };
    snprintf(
        endpoint,
        sizeof(endpoint),
        "%s/%d",
        local_ip,
        ntohs(sin.sin_port));
    char roots[ZTS_STORE_DATA_LEN] = { 0 };
    unsigned int roots_len = 0;
    REQUIRE(
        test_make_roots(root_key, endpoint, TEST_WORLD_ID, roots, &roots_len)
        == ZTS_ERR_OK);

    char storage[1024] = { 0 };
    node_path(storage, sizeof(storage), "node1");
    REQUIRE(zts_init_set_low_bandwidth_mode(1) == ZTS_ERR_OK);
    REQUIRE(zts_init_set_encrypted_hello(encrypted_hello) == ZTS_ERR_OK);
    // Metrics only for the second run, which uses the same storage
    REQUIRE(zts_init_enable_metrics(encrypted_hello) == ZTS_ERR_OK);
    char metrics_path[1200] = { 0 };
    snprintf(metrics_path, sizeof(metrics_path), "%s/metrics.prom", storage);
    start_node(storage, NULL, roots, roots_len);

    uint64_t node_id = zts_node_get_id();
    CHECK(node_id != 0 && node_id < (1ULL << 40));

    // ZTS_EVENT_NODE_UP carries the node ID, bound ports and core version
    CHECK(node_up_info.node_id == node_id);
    CHECK(node_up_info.ver_major == ZEROTIER_ONE_VERSION_MAJOR);
    CHECK(node_up_info.ver_minor == ZEROTIER_ONE_VERSION_MINOR);
    CHECK(node_up_info.ver_rev == ZEROTIER_ONE_VERSION_REVISION);
    CHECK(node_up_info.port_primary == zts_node_get_port());
    CHECK(node_up_info.port_primary > 0);
    CHECK(node_up_info.port_secondary > 0);
    CHECK(node_up_info.port_secondary != node_up_info.port_primary);
    CHECK(node_up_info.port_tertiary == 0);   // port mapping disabled
    printf(
        "node %010llx v%d.%d.%d ports %d/%d/%d\n",
        (unsigned long long)node_id,
        node_up_info.ver_major,
        node_up_info.ver_minor,
        node_up_info.ver_rev,
        node_up_info.port_primary,
        node_up_info.port_secondary,
        node_up_info.port_tertiary);

    // Settings can no longer be changed
    CHECK(zts_init_set_low_bandwidth_mode(0) == ZTS_ERR_SERVICE);
    CHECK(zts_init_set_encrypted_hello(! encrypted_hello) == ZTS_ERR_SERVICE);
    CHECK(zts_init_enable_metrics(! encrypted_hello) == ZTS_ERR_SERVICE);
    CHECK(zts_init_set_roots(roots, roots_len) == ZTS_ERR_SERVICE);

    // Wait for a HELLO addressed to our fake root
    uint8_t pkt[2048];
    int got_hello = 0;
    long long deadline = test_now_ms() + (have_local_ip ? 30000 : 0);
    while (! got_hello && test_now_ms() < deadline) {
        ssize_t n = recv(fake_root, pkt, sizeof(pkt), 0);
        // Header: IV (8), destination (5), source (5), flags (1), MAC (8),
        // verb (1)
        if (n < 28 || read_addr40(pkt + 8) != root_id
            || read_addr40(pkt + 13) != node_id) {
            continue;
        }
        if (encrypted_hello) {
            // Extended armor flag. The verb is encrypted so the root is only
            // ever sent HELLOs before it answers.
            got_hello = 1;
            CHECK((pkt[18] & 0x80) != 0);
            // Cipher suite: Poly1305 without payload encryption, the extended
            // armor provides confidentiality
            CHECK(((pkt[18] >> 3) & 0x07) == 0);
            // Same HELLO as before plus the ephemeral public key (C25519)
            if (plain_hello_len > 0) {
                CHECK(n == plain_hello_len + 32);
            }
            continue;
        }
        // header (28) + proto/version (5) + timestamp (8) + identity address
        // and type (6)
        if (n < 47 || (pkt[27] & 0x1f) != 0x01) {
            continue;
        }
        got_hello = 1;
        plain_hello_len = n;
        CHECK((pkt[18] & 0x80) == 0);              // no extended armor
        CHECK(pkt[28] >= 11);                      // protocol version
        CHECK(pkt[29] == ZEROTIER_ONE_VERSION_MAJOR);
        CHECK(pkt[30] == ZEROTIER_ONE_VERSION_MINOR);
        CHECK(((pkt[31] << 8) | pkt[32]) == ZEROTIER_ONE_VERSION_REVISION);
        // Identity: address (5), type (1), public key (64), secret length (1)
        const uint8_t* id = pkt + 41;
        CHECK(read_addr40(id) == node_id);
        CHECK(id[5] == 0);   // C25519
        // Followed by the destination InetAddress and the planet's world ID
        const uint8_t* ia = id + 5 + 1 + 64 + 1;
        int ia_len = (ia[0] == 0x04) ? 7 : ((ia[0] == 0x06) ? 19 : 1);
        if (n >= (ia - pkt) + ia_len + 8) {
            CHECK(read_u64(ia + ia_len) == TEST_WORLD_ID);
        }
        else {
            CHECK(! "HELLO too short to contain world ID");
        }
    }
    if (have_local_ip) {
        CHECK(got_hello);
    }
    close(fake_root);

    // The fake root never answers so the node can't be online
    CHECK(zts_node_is_online() == 0);

    // Metrics are written every 5s in Prometheus text format, and only if
    // enabled
    if (encrypted_hello) {
        WAIT_FOR(test_file_contains(metrics_path, "zt_packet"), 15000);
        CHECK(test_file_contains(metrics_path, "zt_packet{"));
    }
    else {
        CHECK(! test_file_exists(metrics_path));
    }

    test_stop_node();

    char path[1200] = { 0 };
    snprintf(path, sizeof(path), "%s/identity.secret", storage);
    CHECK(test_file_exists(path));
    snprintf(path, sizeof(path), "%s/identity.public", storage);
    CHECK(test_file_exists(path));
    return node_id;
}

/**
 * Restart right after zts_node_stop() with another identity, several times.
 * The new settings must reach the new node: zts_node_stop() used to return
 * before the old service was torn down, so they could be applied to the dying
 * instance and lost.
 */
static void test_immediate_restart()
{
    TEST_BEGIN("test_immediate_restart");

    char root_key[ZTS_ID_STR_BUF_LEN] = { 0 };
    unsigned int root_key_len = ZTS_ID_STR_BUF_LEN;
    REQUIRE(zts_id_new(root_key, &root_key_len) == ZTS_ERR_OK);
    char roots[ZTS_STORE_DATA_LEN] = { 0 };
    unsigned int roots_len = 0;
    REQUIRE(test_make_roots(root_key, "192.0.2.1/9993", TEST_WORLD_ID, roots, &roots_len) == ZTS_ERR_OK);

    for (int i = 0; i < 3; i++) {
        char key[ZTS_ID_STR_BUF_LEN] = { 0 };
        unsigned int key_len = ZTS_ID_STR_BUF_LEN;
        REQUIRE(zts_id_new(key, &key_len) == ZTS_ERR_OK);
        start_node(NULL, key, roots, roots_len);
        CHECK(zts_node_get_id() == test_id_from_key(key));
        CHECK(node_up_info.node_id == test_id_from_key(key));
        CHECK(zts_node_stop() == ZTS_ERR_OK);
    }
    CHECK(zts_node_stop() == ZTS_ERR_SERVICE);
}

static void test_identity_persistence(uint64_t expected_id)
{
    TEST_BEGIN("test_identity_persistence");

    char root_key[ZTS_ID_STR_BUF_LEN] = { 0 };
    unsigned int root_key_len = ZTS_ID_STR_BUF_LEN;
    REQUIRE(zts_id_new(root_key, &root_key_len) == ZTS_ERR_OK);
    char roots[ZTS_STORE_DATA_LEN] = { 0 };
    unsigned int roots_len = 0;
    // Unreachable root: TEST-NET-1 (RFC 5737)
    REQUIRE(
        test_make_roots(
            root_key,
            "192.0.2.1/9993",
            TEST_WORLD_ID,
            roots,
            &roots_len)
        == ZTS_ERR_OK);

    char storage[1024] = { 0 };
    node_path(storage, sizeof(storage), "node1");
    start_node(storage, NULL, roots, roots_len);
    CHECK(zts_node_get_id() == expected_id);
    CHECK(node_up_info.node_id == expected_id);

    char key[ZTS_ID_STR_BUF_LEN] = { 0 };
    unsigned int key_len = ZTS_ID_STR_BUF_LEN;
    CHECK(zts_node_get_id_pair(key, &key_len) == ZTS_ERR_OK);
    CHECK(zts_id_pair_is_valid(key, ZTS_ID_STR_BUF_LEN) == 1);
    CHECK(test_id_from_key(key) == expected_id);
    test_stop_node();
}

static void check_adhoc_network(
    uint64_t net_id,
    uint64_t node_id,
    uint16_t start_port,
    uint16_t end_port)
{
    CHECK(zts_net_transport_is_ready(net_id) == 1);
    CHECK(zts_net_get_status(net_id) == ZTS_NETWORK_STATUS_OK);
    CHECK(zts_net_get_type(net_id) == ZTS_NETWORK_TYPE_PUBLIC);
    CHECK(zts_net_get_mtu(net_id) >= 1280);

    char expected_name[32] = { 0 };
    snprintf(
        expected_name,
        sizeof(expected_name),
        "adhoc-%04x-%04x",
        start_port,
        end_port);
    char name[ZTS_MAX_NETWORK_SHORT_NAME_LENGTH] = { 0 };
    CHECK(
        zts_net_get_name(net_id, name, ZTS_MAX_NETWORK_SHORT_NAME_LENGTH)
        == ZTS_ERR_OK);
    CHECK(! strcmp(name, expected_name));

    // Ad-hoc networks assign exactly one 6plane IPv6 address and no IPv4
    struct zts_sockaddr_storage expected;
    memset(&expected, 0, sizeof(expected));
    CHECK(zts_addr_compute_6plane(net_id, node_id, &expected) == ZTS_ERR_OK);
    struct zts_sockaddr_storage ss;
    memset(&ss, 0, sizeof(ss));
    CHECK(zts_addr_get(net_id, ZTS_AF_INET6, &ss) == ZTS_ERR_OK);
    CHECK(ip6_equal(&ss, &expected));
    CHECK(zts_addr_is_assigned(net_id, ZTS_AF_INET6) == 1);
    CHECK(zts_addr_is_assigned(net_id, ZTS_AF_INET) == 0);
    struct zts_sockaddr_storage all[ZTS_MAX_ASSIGNED_ADDRESSES];
    unsigned int count = ZTS_MAX_ASSIGNED_ADDRESSES;
    CHECK(zts_addr_get_all(net_id, all, &count) == ZTS_ERR_OK);
    CHECK(count == 1);

    // MAC is rendered as six zero-padded octets
    uint64_t mac = zts_net_get_mac(net_id);
    CHECK(mac != 0 && mac < (1ULL << 48));
    char mac_str[ZTS_MAC_ADDRSTRLEN] = { 0 };
    char expected_mac[ZTS_MAC_ADDRSTRLEN] = { 0 };
    snprintf(
        expected_mac,
        sizeof(expected_mac),
        "%02x:%02x:%02x:%02x:%02x:%02x",
        (unsigned int)((mac >> 40) & 0xff),
        (unsigned int)((mac >> 32) & 0xff),
        (unsigned int)((mac >> 24) & 0xff),
        (unsigned int)((mac >> 16) & 0xff),
        (unsigned int)((mac >> 8) & 0xff),
        (unsigned int)(mac & 0xff));
    CHECK(
        zts_net_get_mac_str(net_id, mac_str, ZTS_MAC_ADDRSTRLEN) == ZTS_ERR_OK);
    CHECK(! strcmp(mac_str, expected_mac));
    CHECK(strlen(mac_str) == 17);
}

/**
 * A node that is its own root is online without any network traffic, which
 * lets us join ad-hoc networks and use the lwIP stack fully offline.
 */
static void test_adhoc_networks()
{
    TEST_BEGIN("test_adhoc_networks");

    char key[ZTS_ID_STR_BUF_LEN] = { 0 };
    unsigned int key_len = ZTS_ID_STR_BUF_LEN;
    REQUIRE(zts_id_new(key, &key_len) == ZTS_ERR_OK);
    uint64_t node_id = test_id_from_key(key);
    char roots[ZTS_STORE_DATA_LEN] = { 0 };
    unsigned int roots_len = 0;
    REQUIRE(
        test_make_roots(key, "192.0.2.1/9993", TEST_WORLD_ID, roots, &roots_len)
        == ZTS_ERR_OK);

    char storage[1024] = { 0 };
    node_path(storage, sizeof(storage), "node2");
    start_node(storage, key, roots, roots_len);
    CHECK(zts_node_get_id() == node_id);
    WAIT_FOR(zts_node_is_online(), 15000);
    REQUIRE(zts_node_is_online());
    CHECK(atomic_load(&ev_node_online));

    uint64_t net_a = zts_net_compute_adhoc_id(ADHOC_A_START, ADHOC_A_END);
    uint64_t net_b = zts_net_compute_adhoc_id(ADHOC_B_START, ADHOC_B_END);
    CHECK(zts_net_join(0) == ZTS_ERR_ARG);
    CHECK(zts_net_join(net_a) == ZTS_ERR_OK);
    WAIT_FOR(atomic_load(&ev_net_ready_ip6), 30000);
    REQUIRE(atomic_load(&ev_net_ready_ip6));
    CHECK(atomic_load(&ev_addr_added_ip6));
    // Previously returned true for an invalid network ID
    CHECK(zts_net_transport_is_ready(0) == 0);
    check_adhoc_network(net_a, node_id, ADHOC_A_START, ADHOC_A_END);

    // Network info delivered with the event matches the queried state
    CHECK(net_ready_info.net_id == net_a);
    CHECK(net_ready_info.status == ZTS_NETWORK_STATUS_OK);
    CHECK(net_ready_info.type == ZTS_NETWORK_TYPE_PUBLIC);
    CHECK(net_ready_info.mac == zts_net_get_mac(net_a));
    CHECK(net_ready_info.mtu == (unsigned int)zts_net_get_mtu(net_a));
    CHECK(net_ready_info.assigned_addr_count == 1);
    CHECK(
        net_ready_info.assigned_addr_count
        && net_ready_info.assigned_addrs[0].ss_family == ZTS_AF_INET6);

    // Sockets can be bound to the assigned address
    char ipstr[ZTS_IP_MAX_STR_LEN] = { 0 };
    CHECK(
        zts_addr_get_str(net_a, ZTS_AF_INET6, ipstr, sizeof(ipstr))
        == ZTS_ERR_OK);
    int tcp = zts_bsd_socket(ZTS_AF_INET6, ZTS_SOCK_STREAM, 0);
    CHECK(tcp >= 0);
    CHECK(zts_bind(tcp, ipstr, ADHOC_A_START) == ZTS_ERR_OK);
    CHECK(zts_listen(tcp, 1) == ZTS_ERR_OK);
    char local[ZTS_IP_MAX_STR_LEN] = { 0 };
    unsigned short local_port = 0;
    CHECK(
        zts_getsockname(tcp, local, sizeof(local), &local_port) == ZTS_ERR_OK);
    CHECK(local_port == ADHOC_A_START);
    CHECK(zts_close(tcp) == ZTS_ERR_OK);
    int udp = zts_bsd_socket(ZTS_AF_INET6, ZTS_SOCK_DGRAM, 0);
    CHECK(udp >= 0);
    CHECK(zts_bind(udp, ipstr, ADHOC_A_START + 1) == ZTS_ERR_OK);
    CHECK(zts_close(udp) == ZTS_ERR_OK);

    // Join a second network, then leave the first
    atomic_store(&ev_net_ready_ip6, 0);
    CHECK(zts_net_join(net_b) == ZTS_ERR_OK);
    WAIT_FOR(
        zts_net_transport_is_ready(net_b) == 1
            && zts_addr_is_assigned(net_b, ZTS_AF_INET6),
        30000);
    check_adhoc_network(net_b, node_id, ADHOC_B_START, ADHOC_B_END);

    char conf_a[1200] = { 0 };
    char conf_b[1200] = { 0 };
    snprintf(
        conf_a,
        sizeof(conf_a),
        "%s/networks.d/%016llx.conf",
        storage,
        (unsigned long long)net_a);
    snprintf(
        conf_b,
        sizeof(conf_b),
        "%s/networks.d/%016llx.conf",
        storage,
        (unsigned long long)net_b);
    CHECK(test_file_exists(conf_a));
    CHECK(test_file_exists(conf_b));

    CHECK(zts_net_leave(net_a) == ZTS_ERR_OK);
    WAIT_FOR(zts_net_get_status(net_a) == ZTS_ERR_NO_RESULT, 10000);
    CHECK(zts_net_get_status(net_a) == ZTS_ERR_NO_RESULT);
    CHECK(zts_addr_is_assigned(net_a, ZTS_AF_INET6) == 0);
    // Leaving must delete the cached config, otherwise the network would be
    // rejoined on the next start
    CHECK(! test_file_exists(conf_a));
    CHECK(test_file_exists(conf_b));
    CHECK(zts_net_transport_is_ready(net_b) == 1);
    test_stop_node();

    // Restart: only the network we did not leave is rejoined. The identity
    // given via zts_init_from_memory() is not written to storage, so provide
    // it again.
    TEST_BEGIN("test_adhoc_networks (restart)");
    start_node(storage, key, roots, roots_len);
    CHECK(zts_node_get_id() == node_id);
    WAIT_FOR(zts_node_is_online(), 15000);
    CHECK(zts_node_is_online());
    WAIT_FOR(
        zts_net_transport_is_ready(net_b) == 1
            && zts_addr_is_assigned(net_b, ZTS_AF_INET6),
        30000);
    check_adhoc_network(net_b, node_id, ADHOC_B_START, ADHOC_B_END);
    CHECK(zts_net_get_status(net_a) == ZTS_ERR_NO_RESULT);
    test_stop_node();
}

int main(int argc, char** argv)
{
    if (argc > 1) {
        snprintf(work_dir, sizeof(work_dir), "%s", argv[1]);
        mkdir(work_dir, 0700);
    }
    else {
        char tmpl[] = "/tmp/libzt-coretest-XXXXXX";
        REQUIRE(mkdtemp(tmpl) != NULL);
        snprintf(work_dir, sizeof(work_dir), "%s", tmpl);
    }
    // zts_util_sign_root_set() looks for signing keys in the working directory
    REQUIRE(chdir(work_dir) == 0);
    printf("work dir: %s\n", work_dir);
    printf(
        "ZeroTier core: %d.%d.%d\n",
        ZEROTIER_ONE_VERSION_MAJOR,
        ZEROTIER_ONE_VERSION_MINOR,
        ZEROTIER_ONE_VERSION_REVISION);

    test_pre_start();
    test_identity_and_addressing();
    test_sign_root_set();
    uint64_t node_id = test_custom_roots_hello(0);
    // Same storage, so the same identity
    CHECK(test_custom_roots_hello(1) == node_id);
    test_identity_persistence(node_id);
    test_immediate_restart();
    test_adhoc_networks();

    return test_summary("coretest");
}
