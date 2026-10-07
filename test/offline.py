"""
Offline test of the libzt Python binding (the Python counterpart of
coretest.c and twonode.c). Needs no Internet access and no controller:

  - Root sets are signed locally, nodes use ad-hoc (controller-less) networks
  - A node that is its own root is online without contacting anyone

Every scenario runs in a child process of its own, as libzt supports only one
node per process.

Usage: python3 test/offline.py   (after installing the libzt wheel)
"""

import ctypes
import ipaddress
import os
import socket as pysocket
import subprocess
import sys
import tempfile
import time

import libzt
import libzt._libzt

ADHOC_START = 9000
ADHOC_END = 9100
WORLD_ID = 0x0000C0FFEE15600D
ID_STR_BUF_LEN = 384
STORE_DATA_LEN = 4096

checks = 0
failures = 0


def check(cond, what):
    global checks, failures
    checks += 1
    if not cond:
        failures += 1
        print("FAIL: " + what, flush=True)


def wait_for(predicate, timeout):
    deadline = time.monotonic() + timeout
    while not predicate() and time.monotonic() < deadline:
        time.sleep(0.05)
    return predicate()


def summary(name):
    print("%s: %d checks, %d failures" % (name, checks, failures), flush=True)
    return 1 if failures else 0


#
# Helpers that need raw buffers are called through ctypes. The extension module
# is already loaded, so this binds to the same library instance.
#

_lib = ctypes.CDLL(libzt._libzt.__file__)


class RootSet(ctypes.Structure):
    _fields_ = [
        ("public_id_str", ctypes.c_char_p * 16),
        ("endpoint_ip_str", (ctypes.c_char_p * 32) * 16),
    ]


def new_identity():
    key = ctypes.create_string_buffer(ID_STR_BUF_LEN)
    key_len = ctypes.c_uint(ID_STR_BUF_LEN)
    assert _lib.zts_id_new(key, ctypes.byref(key_len)) == libzt.ZTS_ERR_OK
    return key.value.decode()


def make_roots(root_key, endpoint):
    """Sign a root set with a single root (signing keys go to the cwd)"""
    spec = RootSet()
    spec.public_id_str[0] = ":".join(root_key.split(":")[:3]).encode()
    spec.endpoint_ip_str[0][0] = endpoint.encode()
    roots = ctypes.create_string_buffer(STORE_DATA_LEN)
    roots_len = ctypes.c_uint(STORE_DATA_LEN)
    prev_key = ctypes.create_string_buffer(256)
    prev_key_len = ctypes.c_uint(256)
    curr_key = ctypes.create_string_buffer(256)
    curr_key_len = ctypes.c_uint(256)
    err = _lib.zts_util_sign_root_set(
        roots,
        ctypes.byref(roots_len),
        prev_key,
        ctypes.byref(prev_key_len),
        curr_key,
        ctypes.byref(curr_key_len),
        ctypes.c_uint64(WORLD_ID),
        ctypes.c_uint64(1),
        ctypes.byref(spec),
    )
    assert err == libzt.ZTS_ERR_OK
    return roots.raw[: roots_len.value]


def compute_6plane(net_id, node_id):
    # The buffer length must be exactly ZTS_IP_MAX_STR_LEN
    buf = ctypes.create_string_buffer(libzt.ZTS_IP_MAX_STR_LEN)
    err = _lib.zts_addr_compute_6plane_str(
        ctypes.c_uint64(net_id),
        ctypes.c_uint64(node_id),
        buf,
        ctypes.c_uint(libzt.ZTS_IP_MAX_STR_LEN),
    )
    assert err == libzt.ZTS_ERR_OK
    return buf.value.decode()


def node_id_from_key(key):
    return int(key[:10], 16)


def free_udp_port():
    s = pysocket.socket(pysocket.AF_INET, pysocket.SOCK_DGRAM)
    s.bind(("0.0.0.0", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def local_ipv4():
    """An address of this host the node binds to. Packets the node sends to
    127.0.0.1 are not delivered locally (sockets are bound to interfaces)."""
    s = pysocket.socket(pysocket.AF_INET, pysocket.SOCK_DGRAM)
    try:
        s.connect(("192.0.2.1", 9))  # TEST-NET-1, nothing is sent
        ip = s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()
    return None if ip.startswith("127.") or ip.startswith("169.254.") else ip


class Events:
    def __init__(self):
        self.seen = {}

    def __call__(self, event_code, id):
        self.seen.setdefault(event_code, []).append(id)

    def got(self, event_code, id=None):
        ids = self.seen.get(event_code, [])
        return bool(ids) if id is None else id in ids


def start_node(work_dir, key, roots, port):
    events = Events()
    node = libzt.ZeroTierNode()
    node.init_set_event_handler(events)
    assert _lib.zts_init_from_memory(key.encode(), ctypes.c_uint(ID_STR_BUF_LEN)) == 0
    assert _lib.zts_init_set_roots(roots, ctypes.c_uint(len(roots))) == 0
    assert libzt.zts_init_allow_port_mapping(0) == libzt.ZTS_ERR_OK
    assert node.init_set_port(port) == libzt.ZTS_ERR_OK
    assert node.node_start() == libzt.ZTS_ERR_OK
    return node, events


def join_adhoc(node, events, net_id):
    check(node.net_join(net_id) == libzt.ZTS_ERR_OK, "net_join")
    ready = wait_for(
        lambda: node.net_transport_is_ready(net_id) == 1
        and libzt.zts_addr_is_assigned(net_id, libzt.ZTS_AF_INET6) == 1,
        30,
    )
    check(ready, "ad-hoc network ready")
    return ready


#
# Scenario 1: single self-rooted node
#


def run_single(work_dir):
    key = new_identity()
    node_id = node_id_from_key(key)
    port = free_udp_port()
    roots = make_roots(key, "127.0.0.1/%d" % port)

    # Before start
    node = libzt.ZeroTierNode()
    check(node.init_set_encrypted_hello(True) == libzt.ZTS_ERR_OK, "encrypted hello")
    check(node.init_set_low_bandwidth_mode(True) == libzt.ZTS_ERR_OK, "low bandwidth")
    check(node.node_is_online() == 0, "offline before start")
    net_id = libzt.zts_net_compute_adhoc_id(ADHOC_START, ADHOC_END)
    check(net_id == 0xFF2328238C000000, "ad-hoc network ID")

    node, events = start_node(work_dir, key, roots, port)
    check(wait_for(node.node_is_online, 15), "self-rooted node online")
    check(node.node_id() == node_id, "node ID")
    check(wait_for(lambda: events.got(libzt.ZTS_EVENT_NODE_ONLINE, node_id), 5), "ZTS_EVENT_NODE_ONLINE")
    check(
        node.init_set_encrypted_hello(False) == libzt.ZTS_ERR_SERVICE,
        "encrypted hello can't be changed after start",
    )

    if not join_adhoc(node, events, net_id):
        return summary("single")
    check(wait_for(lambda: events.got(libzt.ZTS_EVENT_NETWORK_READY_IP6, net_id), 5), "ZTS_EVENT_NETWORK_READY_IP6")
    ip6 = node.addr_get_ipv6(net_id)
    check(
        ipaddress.ip_address(ip6) == ipaddress.ip_address(compute_6plane(net_id, node_id)),
        "6plane address " + ip6,
    )

    s = libzt.socket(libzt.ZTS_AF_INET6, libzt.ZTS_SOCK_DGRAM, 0)
    s.bind((ip6, ADHOC_START + 1))
    name = s.getsockname()
    check(
        len(name) == 4
        and ipaddress.ip_address(name[0]) == ipaddress.ip_address(ip6)
        and name[1] == ADHOC_START + 1,
        "getsockname() %r" % (name,),
    )

    # select() timeouts (this used the CPython private _PyTime API)
    t0 = time.monotonic()
    r, w, x = libzt.select().select([s], [], [], 0.3)
    elapsed = time.monotonic() - t0
    check(r == [] and w == [] and x == [], "idle select() returns nothing")
    check(0.25 <= elapsed < 2.0, "select() honours the timeout (%.3fs)" % elapsed)
    for bad, exc in ((-1, ValueError), ("x", TypeError), (float("nan"), ValueError)):
        try:
            libzt.select().select([s], [], [], bad)
            check(False, "select() rejects timeout %r" % (bad,))
        except exc:
            pass

    # Socket timeouts
    check(s.gettimeout() is None, "blocking by default")
    s.settimeout(0.5)
    check(s.gettimeout() == 0.5, "gettimeout() == 0.5 (%r)" % s.gettimeout())
    t0 = time.monotonic()
    try:
        s.recv(100)
        check(False, "recv() times out")
    except TimeoutError:
        elapsed = time.monotonic() - t0
        check(0.4 <= elapsed < 3.0, "recv() honours the timeout (%.3fs)" % elapsed)
    s.settimeout(0)
    check(s.gettimeout() == 0.0, "non-blocking: gettimeout() == 0.0")
    t0 = time.monotonic()
    try:
        s.recv(100)
        check(False, "non-blocking recv() fails")
    except BlockingIOError:
        check(time.monotonic() - t0 < 0.5, "non-blocking recv() returns immediately")
    s.settimeout(None)
    check(s.gettimeout() is None, "blocking again")
    s.close()

    # Returns once the node is down, ZTS_EVENT_NODE_DOWN has been delivered
    # (this used to take 30s: the event handler waited for the GIL held by
    # the caller)
    t0 = time.monotonic()
    check(node.node_stop() == libzt.ZTS_ERR_OK, "node_stop()")
    elapsed = time.monotonic() - t0
    check(elapsed < 5, "node_stop() took %.2fs" % elapsed)
    check(events.got(libzt.ZTS_EVENT_NODE_DOWN), "ZTS_EVENT_NODE_DOWN")
    return summary("single")


#
# Scenario 2: two nodes, TCP over the ad-hoc network
#

PAYLOAD = bytes((i * 31 + 7) & 0xFF for i in range(64 * 1024))


def recv_exactly(s, n):
    data = b""
    while len(data) < n:
        chunk = s.recv(min(65536, n - len(data)))
        if not chunk:
            break
        data += chunk
    return data


def run_peer(work_dir, role):
    keys = {r: open(os.path.join(work_dir, r + ".key")).read() for r in ("a", "b")}
    roots = open(os.path.join(work_dir, "roots"), "rb").read()
    port_a = int(open(os.path.join(work_dir, "port_a")).read())
    net_id = libzt.zts_net_compute_adhoc_id(ADHOC_START, ADHOC_END)
    id_a = node_id_from_key(keys["a"])
    id_b = node_id_from_key(keys["b"])
    ip6_a = compute_6plane(net_id, id_a)
    ip6_b = compute_6plane(net_id, id_b)

    node, events = start_node(work_dir, keys[role], roots, port_a if role == "a" else free_udp_port())
    if not wait_for(node.node_is_online, 60):
        check(False, "[%s] online" % role)
        return summary(role)
    if not join_adhoc(node, events, net_id):
        return summary(role)

    def same_ip(addr, ip):
        return addr is not None and ipaddress.ip_address(addr[0]) == ipaddress.ip_address(ip)

    if role == "a":
        udp = libzt.socket(libzt.ZTS_AF_INET6, libzt.ZTS_SOCK_DGRAM, 0)
        udp.bind((ip6_a, ADHOC_START + 2))
        srv = libzt.socket(libzt.ZTS_AF_INET6, libzt.ZTS_SOCK_STREAM, 0)
        srv.bind((ip6_a, ADHOC_START + 1))
        srv.listen(1)
        conn, addr = srv.accept()
        check(
            ipaddress.ip_address(addr) == ipaddress.ip_address(ip6_b),
            "[a] accepted IPv6 peer address " + addr,
        )
        check(same_ip(conn.getpeername(), ip6_b), "[a] getpeername() %r" % (conn.getpeername(),))
        check(conn.getsockname()[1] == ADHOC_START + 1, "[a] getsockname() %r" % (conn.getsockname(),))
        data = recv_exactly(conn, len(PAYLOAD))
        check(data == PAYLOAD, "[a] received payload (%d bytes)" % len(data))
        conn.sendall(data)
        # Wait for the client to close
        check(conn.recv(1) == b"", "[a] client closed")
        conn.close()
        srv.close()

        # UDP echo until the client says bye
        udp.settimeout(30)
        echoed = 0
        while True:
            try:
                data, peer = udp.recvfrom(1500)
            except TimeoutError:
                break
            if data == b"bye":
                break
            check(same_ip(peer, ip6_b), "[a] recvfrom() sender %r" % (peer,))
            udp.sendto(data, peer)
            echoed += 1
        check(echoed > 0, "[a] echoed UDP datagrams")
        udp.close()
    else:
        c = libzt.socket(libzt.ZTS_AF_INET6, libzt.ZTS_SOCK_STREAM, 0)
        deadline = time.monotonic() + 60
        while True:
            try:
                c.connect((ip6_a, ADHOC_START + 1))
                break
            except (ConnectionError, BlockingIOError):
                if time.monotonic() > deadline:
                    raise
                c.close()
                time.sleep(0.5)
                c = libzt.socket(libzt.ZTS_AF_INET6, libzt.ZTS_SOCK_STREAM, 0)
        c.settimeout(30)
        check(same_ip(c.getpeername(), ip6_a), "[b] getpeername() %r" % (c.getpeername(),))
        check(same_ip(c.getsockname(), ip6_b), "[b] getsockname() %r" % (c.getsockname(),))
        c.sendall(PAYLOAD)
        data = recv_exactly(c, len(PAYLOAD))
        check(data == PAYLOAD, "[b] echoed payload (%d bytes)" % len(data))
        c.close()

        # UDP round trip, datagrams may be lost so retry
        udp = libzt.socket(libzt.ZTS_AF_INET6, libzt.ZTS_SOCK_DGRAM, 0)
        udp.bind((ip6_b, ADHOC_START + 3))
        udp.settimeout(1)
        reply = None
        for i in range(20):
            msg = b"ping %d" % i
            check(udp.sendto(msg, (ip6_a, ADHOC_START + 2)) == len(msg), "[b] sendto()")
            try:
                reply, peer = udp.recvfrom(1500)
            except TimeoutError:
                continue
            check(reply == msg, "[b] UDP echo %r" % (reply,))
            check(same_ip(peer, ip6_a) and peer[1] == ADHOC_START + 2, "[b] recvfrom() sender %r" % (peer,))
            break
        check(reply is not None, "[b] got a UDP reply")
        for _ in range(3):
            udp.sendto(b"bye", 0, (ip6_a, ADHOC_START + 2))
        udp.close()

    node.node_stop()
    return summary(role)


def run_child(role, work_dir):
    return subprocess.Popen([sys.executable, os.path.abspath(__file__), role, work_dir])


def main():
    if len(sys.argv) == 3:
        role, work_dir = sys.argv[1], sys.argv[2]
        os.chdir(work_dir)
        code = run_single(work_dir) if role == "single" else run_peer(work_dir, role)
        sys.stdout.flush()
        # Skip static destructors, which may block while the node shuts down
        os._exit(code)

    work_dir = tempfile.mkdtemp(prefix="libzt-pytest-")
    print("work dir: " + work_dir, flush=True)
    result = 0

    print("\n*** single node", flush=True)
    single = run_child("single", work_dir)
    result |= single.wait(timeout=240) != 0

    print("\n*** two nodes", flush=True)
    ip = local_ipv4()
    if ip is None:
        print("SKIP: no usable IPv4 interface")
    else:
        os.chdir(work_dir)
        for r in ("a", "b"):
            with open(os.path.join(work_dir, r + ".key"), "w") as f:
                f.write(new_identity())
        port_a = free_udp_port()
        with open(os.path.join(work_dir, "port_a"), "w") as f:
            f.write(str(port_a))
        with open(os.path.join(work_dir, "roots"), "wb") as f:
            key_a = open(os.path.join(work_dir, "a.key")).read()
            f.write(make_roots(key_a, "%s/%d" % (ip, port_a)))
        a = run_child("a", work_dir)
        b = run_child("b", work_dir)
        for p in (b, a):
            try:
                result |= p.wait(timeout=240) != 0
            except subprocess.TimeoutExpired:
                print("FAIL: timeout")
                a.kill()
                b.kill()
                result = 1

    print("\noffline.py: " + ("FAILED" if result else "OK"))
    sys.stdout.flush()
    os._exit(1 if result else 0)


if __name__ == "__main__":
    main()
