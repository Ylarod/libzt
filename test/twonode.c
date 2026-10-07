/**
 * Two-node integration test that runs entirely on this host.
 *
 * Node A is the only root in a locally signed root set and node B uses A as
 * its root, so B comes online by talking to A over UDP on a local interface
 * address. Both join the same ad-hoc network and exchange TCP and UDP traffic
 * over their 6plane IPv6 addresses. No Internet access or network controller
 * is required, but the host needs a non-loopback IPv4 interface.
 *
 * libzt supports one node per process, so each node runs in a forked child.
 *
 * Usage: twonode
 *
 * Exit codes: 0 on success, 1 on failure, 77 if the test cannot run here.
 */

#include "testutil.h"
#include "version.h"

#include <ZeroTierSockets.h>
#include <signal.h>
#include <stdatomic.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#define ADHOC_START 9000
#define ADHOC_END   9100
#define TCP_PORT    9000
#define UDP_PORT    9001

#define CHUNK_LEN  1024
#define NUM_CHUNKS 32

#define TEST_WORLD_ID 0x0000c0ffee15600dULL

#define SKIP_RETURN_CODE 77

// Shared setup created by the parent before forking
static char key_a[ZTS_ID_STR_BUF_LEN];
static char key_b[ZTS_ID_STR_BUF_LEN];
static uint64_t id_a;
static uint64_t id_b;
static char roots[ZTS_STORE_DATA_LEN];
static unsigned int roots_len;
static char local_ip[INET_ADDRSTRLEN];
static int port_a;
static uint64_t net_id;

//----------------------------------------------------------------------------//
// Events                                                                     //
//----------------------------------------------------------------------------//

static uint64_t expected_peer;
static atomic_int ev_node_online;
static atomic_int ev_peer_direct;
static zts_peer_info_t peer_info;

static void on_zts_event(void* ptr)
{
    zts_event_msg_t* msg = (zts_event_msg_t*)ptr;
    switch (msg->event_code) {
        case ZTS_EVENT_NODE_ONLINE:
            atomic_store(&ev_node_online, 1);
            break;
        case ZTS_EVENT_PEER_DIRECT:
        case ZTS_EVENT_PEER_PATH_DISCOVERED:
            if (msg->peer && msg->peer->peer_id == expected_peer
                && msg->peer->path_count > 0
                && ! atomic_load(&ev_peer_direct)) {
                memcpy(&peer_info, msg->peer, sizeof(peer_info));
                atomic_store(&ev_peer_direct, 1);
            }
            break;
        default:
            break;
    }
}

//----------------------------------------------------------------------------//
// Helpers                                                                    //
//----------------------------------------------------------------------------//

static void fill_pattern(uint8_t* buf, size_t len, unsigned int seed)
{
    for (size_t i = 0; i < len; i++) {
        buf[i] = (uint8_t)((i * 31 + seed * 7) & 0xff);
    }
}

static int send_all(int fd, const uint8_t* buf, size_t len)
{
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = zts_bsd_send(fd, buf + sent, len - sent, 0);
        if (n <= 0) {
            return -1;
        }
        sent += (size_t)n;
    }
    return 0;
}

static int recv_all(int fd, uint8_t* buf, size_t len)
{
    size_t got = 0;
    while (got < len) {
        ssize_t n = zts_bsd_recv(fd, buf + got, len - got, 0);
        if (n <= 0) {
            return -1;
        }
        got += (size_t)n;
    }
    return 0;
}

static void
start_and_join(const char* name, const char* key, uint64_t peer, int port)
{
    expected_peer = peer;
    REQUIRE(zts_init_from_memory(key, ZTS_ID_STR_BUF_LEN) == ZTS_ERR_OK);
    REQUIRE(zts_init_set_event_handler(&on_zts_event) == ZTS_ERR_OK);
    REQUIRE(zts_init_set_roots(roots, roots_len) == ZTS_ERR_OK);
    REQUIRE(zts_init_allow_port_mapping(0) == ZTS_ERR_OK);
    if (port) {
        REQUIRE(zts_init_set_port((unsigned short)port) == ZTS_ERR_OK);
    }
    REQUIRE(zts_node_start() == ZTS_ERR_OK);
    WAIT_FOR(zts_node_is_online(), 60000);
    REQUIRE(zts_node_is_online());
    printf(
        "[%s] online as %010llx\n",
        name,
        (unsigned long long)zts_node_get_id());
    REQUIRE(zts_net_join(net_id) == ZTS_ERR_OK);
    WAIT_FOR(
        zts_net_transport_is_ready(net_id) == 1
            && zts_addr_is_assigned(net_id, ZTS_AF_INET6),
        60000);
    REQUIRE(zts_addr_is_assigned(net_id, ZTS_AF_INET6));
}

/**
 * Check the peer info delivered with ZTS_EVENT_PEER_DIRECT. This exercises the
 * conversion from the core's ZT_Peer structure, which has a different layout.
 */
static void
check_peer_info(const char* name, int expected_role, int expected_port)
{
    WAIT_FOR(atomic_load(&ev_peer_direct), 60000);
    REQUIRE(atomic_load(&ev_peer_direct));
    printf(
        "[%s] peer %010llx v%d.%d.%d role %d latency %d paths %u\n",
        name,
        (unsigned long long)peer_info.peer_id,
        peer_info.ver_major,
        peer_info.ver_minor,
        peer_info.ver_rev,
        peer_info.role,
        peer_info.latency,
        peer_info.path_count);
    CHECK(peer_info.peer_id == expected_peer);
    // Both nodes run the same core
    CHECK(peer_info.ver_major == ZEROTIER_ONE_VERSION_MAJOR);
    CHECK(peer_info.ver_minor == ZEROTIER_ONE_VERSION_MINOR);
    CHECK(peer_info.ver_rev == ZEROTIER_ONE_VERSION_REVISION);
    CHECK((int)peer_info.role == expected_role);
    CHECK(
        peer_info.path_count >= 1
        && peer_info.path_count <= ZTS_MAX_PEER_NETWORK_PATHS);

    int found_local_path = 0;
    for (unsigned int i = 0;
         i < peer_info.path_count && i < ZTS_MAX_PEER_NETWORK_PATHS;
         i++) {
        const zts_path_t* p = &peer_info.paths[i];
        CHECK(
            p->address.ss_family == ZTS_AF_INET
            || p->address.ss_family == ZTS_AF_INET6);
        CHECK(p->ifname == NULL);
        if (p->address.ss_family != ZTS_AF_INET) {
            continue;
        }
        const struct zts_sockaddr_in* in4 =
            (const struct zts_sockaddr_in*)&p->address;
        char ipstr[ZTS_INET_ADDRSTRLEN] = { 0 };
        zts_inet_ntop(ZTS_AF_INET, &in4->sin_addr, ipstr, sizeof(ipstr));
        int port = ntohs(in4->sin_port);
        printf(
            "[%s]   path %s/%d last_rx %llu\n",
            name,
            ipstr,
            port,
            (unsigned long long)p->last_rx);
        if (! strcmp(ipstr, local_ip)
            && (expected_port == 0 || port == expected_port)) {
            found_local_path = 1;
            CHECK(p->last_rx > 0);
            CHECK(! p->expired);
        }
    }
    CHECK(found_local_path);
}

//----------------------------------------------------------------------------//
// Node A: root and server                                                    //
//----------------------------------------------------------------------------//

static int run_node_a()
{
    start_and_join("A", key_a, id_b, port_a);
    CHECK(zts_node_get_id() == id_a);
    CHECK(zts_node_get_port() == port_a);

    char ip6[ZTS_IP_MAX_STR_LEN] = { 0 };
    CHECK(
        zts_addr_compute_6plane_str(net_id, id_a, ip6, sizeof(ip6))
        == ZTS_ERR_OK);

    int udp = zts_bsd_socket(ZTS_AF_INET6, ZTS_SOCK_DGRAM, 0);
    REQUIRE(udp >= 0);
    REQUIRE(zts_bind(udp, ip6, UDP_PORT) == ZTS_ERR_OK);

    // TCP echo server, one client
    int srv = zts_bsd_socket(ZTS_AF_INET6, ZTS_SOCK_STREAM, 0);
    REQUIRE(srv >= 0);
    REQUIRE(zts_bind(srv, ip6, TCP_PORT) == ZTS_ERR_OK);
    REQUIRE(zts_listen(srv, 1) == ZTS_ERR_OK);
    char remote[ZTS_IP_MAX_STR_LEN] = { 0 };
    unsigned short remote_port = 0;
    int cli = zts_accept(srv, remote, sizeof(remote), &remote_port);
    REQUIRE(cli >= 0);
    printf("[A] accepted TCP connection from [%s]:%d\n", remote, remote_port);
    CHECK(zts_util_get_ip_family(remote) == ZTS_AF_INET6);
    uint8_t buf[CHUNK_LEN];
    int echoed = 0;
    for (int i = 0; i < NUM_CHUNKS; i++) {
        if (recv_all(cli, buf, CHUNK_LEN) != 0
            || send_all(cli, buf, CHUNK_LEN) != 0) {
            break;
        }
        echoed++;
    }
    CHECK(echoed == NUM_CHUNKS);
    zts_close(cli);
    zts_close(srv);

    // UDP echo until the client says goodbye
    CHECK(zts_set_recv_timeout(udp, 1, 0) == ZTS_ERR_OK);
    int udp_echoed = 0;
    long long deadline = test_now_ms() + 60000;
    while (test_now_ms() < deadline) {
        struct zts_sockaddr_storage from;
        zts_socklen_t from_len = sizeof(from);
        ssize_t n = zts_bsd_recvfrom(
            udp,
            buf,
            sizeof(buf),
            0,
            (struct zts_sockaddr*)&from,
            &from_len);
        if (n <= 0) {
            continue;
        }
        if (n == 3 && ! memcmp(buf, "BYE", 3)) {
            break;
        }
        if (zts_bsd_sendto(
                udp,
                buf,
                (size_t)n,
                0,
                (struct zts_sockaddr*)&from,
                from_len)
            == n) {
            udp_echoed++;
        }
    }
    CHECK(udp_echoed > 0);
    zts_close(udp);

    // A sees B as an ordinary leaf, at some port of B's on our local address
    check_peer_info("A", ZTS_PEER_ROLE_LEAF, 0);

    test_stop_node();
    return test_summary("twonode[A]");
}

//----------------------------------------------------------------------------//
// Node B: leaf and client                                                    //
//----------------------------------------------------------------------------//

static int run_node_b()
{
    start_and_join("B", key_b, id_a, 0);
    CHECK(zts_node_get_id() == id_b);

    // B learned about A from the root set, so A is a planetary root
    check_peer_info("B", ZTS_PEER_ROLE_PLANET, port_a);

    char ip6_a[ZTS_IP_MAX_STR_LEN] = { 0 };
    CHECK(
        zts_addr_compute_6plane_str(net_id, id_a, ip6_a, sizeof(ip6_a))
        == ZTS_ERR_OK);

    // TCP: connect (A may still be setting up) and verify the echo
    int fd = -1;
    long long deadline = test_now_ms() + 60000;
    while (test_now_ms() < deadline) {
        fd = zts_bsd_socket(ZTS_AF_INET6, ZTS_SOCK_STREAM, 0);
        REQUIRE(fd >= 0);
        if (zts_connect(fd, ip6_a, TCP_PORT, 5000) == ZTS_ERR_OK) {
            break;
        }
        zts_close(fd);
        fd = -1;
        zts_util_delay(500);
    }
    REQUIRE(fd >= 0);
    printf("[B] connected to [%s]:%d\n", ip6_a, TCP_PORT);
    uint8_t out[CHUNK_LEN];
    uint8_t in[CHUNK_LEN];
    int matched = 0;
    for (int i = 0; i < NUM_CHUNKS; i++) {
        fill_pattern(out, sizeof(out), (unsigned int)i);
        if (send_all(fd, out, sizeof(out)) != 0
            || recv_all(fd, in, sizeof(in)) != 0) {
            break;
        }
        if (! memcmp(out, in, sizeof(out))) {
            matched++;
        }
    }
    CHECK(matched == NUM_CHUNKS);
    zts_close(fd);

    // UDP: datagrams may be lost, so retry until one is echoed
    int udp = zts_bsd_socket(ZTS_AF_INET6, ZTS_SOCK_DGRAM, 0);
    REQUIRE(udp >= 0);
    CHECK(zts_set_recv_timeout(udp, 1, 0) == ZTS_ERR_OK);
    struct zts_sockaddr_in6 dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin6_len = sizeof(dst);
    dst.sin6_family = ZTS_AF_INET6;
    dst.sin6_port = htons(UDP_PORT);
    zts_inet_pton(ZTS_AF_INET6, ip6_a, &dst.sin6_addr);
    int udp_ok = 0;
    deadline = test_now_ms() + 30000;
    for (int i = 0; ! udp_ok && test_now_ms() < deadline; i++) {
        char msg[64] = { 0 };
        int len = snprintf(
            msg,
            sizeof(msg),
            "datagram %d from %010llx",
            i,
            (unsigned long long)id_b);
        zts_bsd_sendto(
            udp,
            msg,
            (size_t)len,
            0,
            (struct zts_sockaddr*)&dst,
            sizeof(dst));
        char reply[64] = { 0 };
        ssize_t n = zts_bsd_recvfrom(udp, reply, sizeof(reply), 0, NULL, NULL);
        udp_ok = (n == len && ! memcmp(msg, reply, (size_t)len));
    }
    CHECK(udp_ok);
    for (int i = 0; i < 5; i++) {
        zts_bsd_sendto(
            udp,
            "BYE",
            3,
            0,
            (struct zts_sockaddr*)&dst,
            sizeof(dst));
        zts_util_delay(100);
    }
    zts_close(udp);

    test_stop_node();
    return test_summary("twonode[B]");
}

//----------------------------------------------------------------------------//
// Parent                                                                     //
//----------------------------------------------------------------------------//

static int pick_free_udp_port()
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    socklen_t len = sizeof(sin);
    int port = 0;
    if (fd >= 0 && bind(fd, (struct sockaddr*)&sin, sizeof(sin)) == 0
        && getsockname(fd, (struct sockaddr*)&sin, &len) == 0) {
        port = ntohs(sin.sin_port);
    }
    if (fd >= 0) {
        close(fd);
    }
    return port;
}

static pid_t spawn(int (*fn)())
{
    fflush(stdout);
    pid_t pid = fork();
    if (pid == 0) {
        alarm(240);   // never outlive the parent's timeout
        int code = fn();
        fflush(stdout);
        fflush(stderr);
        // Skip static destructors: the core's global metrics saver joins a
        // worker thread that was started in the parent and doesn't exist here
        _exit(code);
    }
    return pid;
}

int main()
{
    setvbuf(stdout, NULL, _IOLBF, 0);
    if (! test_find_local_ipv4(local_ip, sizeof(local_ip))) {
        printf("SKIP: no usable IPv4 interface\n");
        return SKIP_RETURN_CODE;
    }
    port_a = pick_free_udp_port();
    REQUIRE(port_a > 0);

    unsigned int len = ZTS_ID_STR_BUF_LEN;
    REQUIRE(zts_id_new(key_a, &len) == ZTS_ERR_OK);
    len = ZTS_ID_STR_BUF_LEN;
    REQUIRE(zts_id_new(key_b, &len) == ZTS_ERR_OK);
    id_a = test_id_from_key(key_a);
    id_b = test_id_from_key(key_b);

    char endpoint[64] = { 0 };
    snprintf(endpoint, sizeof(endpoint), "%s/%d", local_ip, port_a);
    REQUIRE(
        test_make_roots(key_a, endpoint, TEST_WORLD_ID, roots, &roots_len)
        == ZTS_ERR_OK);
    net_id = zts_net_compute_adhoc_id(ADHOC_START, ADHOC_END);

    printf(
        "root A %010llx at %s, leaf B %010llx, network %016llx\n",
        (unsigned long long)id_a,
        endpoint,
        (unsigned long long)id_b,
        (unsigned long long)net_id);

    pid_t pids[2];
    pids[0] = spawn(run_node_a);
    pids[1] = spawn(run_node_b);

    int ok = 1;
    int remaining = 2;
    long long deadline = test_now_ms() + 300000;
    while (remaining > 0 && test_now_ms() < deadline) {
        for (int i = 0; i < 2; i++) {
            int status = 0;
            if (pids[i] > 0 && waitpid(pids[i], &status, WNOHANG) == pids[i]) {
                int code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
                if (WIFSIGNALED(status)) {
                    printf(
                        "node %c killed by signal %d\n",
                        i ? 'B' : 'A',
                        WTERMSIG(status));
                }
                else {
                    printf("node %c exited with %d\n", i ? 'B' : 'A', code);
                }
                ok = ok && code == 0;
                pids[i] = 0;
                remaining--;
            }
        }
        if (! ok) {
            break;   // the other node would only wait for its peer
        }
        usleep(100000);
    }
    for (int i = 0; i < 2; i++) {
        if (pids[i] > 0) {
            printf(
                "node %c %s\n",
                i ? 'B' : 'A',
                ok ? "timed out" : "killed after peer failure");
            kill(pids[i], SIGKILL);
            waitpid(pids[i], NULL, 0);
            ok = 0;
        }
    }
    printf("\ntwonode: %s\n", ok ? "SUCCESS" : "FAILURE");
    return ok ? 0 : 1;
}
