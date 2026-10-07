/*
 * Copyright (c)2013-2021 ZeroTier, Inc.
 *
 * Use of this software is governed by the Business Source License included
 * in the LICENSE.TXT file in the project's root directory.
 *
 * Change Date: 2026-01-01
 *
 * On the date above, in accordance with the Business Source License, use
 * of this software will be governed by version 2.0 of the Apache License.
 */
/****/

/**
 * @file
 *
 * ZeroTier Socket API (Python)
 *
 * This code derives from the Python standard library:
 *
 * Lib/socket.py
 * Modules/socketmodule.c
 * Modules/fcntlmodule.c
 * Modules/clinic/fcntlmodule.c.h
 * Modules/clinic/selectmodule.c.h
 *
 * Copyright and license text can be found in pypi packaging directory.
 *
 */

#include "ZeroTierSockets.h"

#ifdef ZTS_ENABLE_PYTHON

#include "Python.h"
#include "PythonSockets.h"
#include "lwip/inet.h"
#include "lwip/sockets.h"
#include "structmember.h"   // PyMemberDef

#include <math.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

PyObject* set_error(void)
{
    return NULL;   // PyErr_SetFromErrno(zts_errno);
}

/*
 * Timekeeping
 *
 * The CPython private _PyTime_* API previously used here was removed from the
 * public headers in Python 3.13, so use our own nanosecond clock instead.
 */

static int64_t zts_py_monotonic_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000000000 + ts.tv_nsec;
}

/* Convert a timeout in seconds (int or float) to nanoseconds, rounding up.
   Returns -1 and sets the Python exception on error. */
static int zts_py_timeout_from_object(PyObject* obj, int64_t* ns)
{
    double secs = PyFloat_AsDouble(obj);
    if (secs == -1.0 && PyErr_Occurred()) {
        if (PyErr_ExceptionMatches(PyExc_TypeError)) {
            PyErr_SetString(PyExc_TypeError, "timeout must be a float or None");
        }
        return -1;
    }
    if (isnan(secs)) {
        PyErr_SetString(PyExc_ValueError, "Invalid value NaN (not a number)");
        return -1;
    }
    if (secs < 0) {
        PyErr_SetString(PyExc_ValueError, "timeout must be non-negative");
        return -1;
    }
    if (secs > (double)(INT64_MAX / 1000000000)) {
        PyErr_SetString(PyExc_OverflowError, "timeout doesn't fit into C timeval");
        return -1;
    }
    *ns = (int64_t)ceil(secs * 1e9);
    return 0;
}

/* Read SO_RCVTIMEO or SO_SNDTIMEO in nanoseconds (0 means no timeout).
   zts_get_recv_timeout() and zts_get_send_timeout() only report whole
   seconds, so query the option directly. */
static int zts_py_get_timeout_ns(int fd, int optname, int64_t* ns)
{
    struct timeval tv;
    memset(&tv, 0, sizeof(tv));
    zts_socklen_t optlen = sizeof(tv);
    int res = zts_bsd_getsockopt(fd, ZTS_SOL_SOCKET, optname, (void*)&tv, &optlen);
    if (res < 0) {
        return res;
    }
    *ns = (int64_t)tv.tv_sec * 1000000000 + (int64_t)tv.tv_usec * 1000;
    return ZTS_ERR_OK;
}

static int zts_py_set_timeout_ns(int fd, int optname, int64_t ns)
{
    struct timeval tv;
    memset(&tv, 0, sizeof(tv));
    int64_t us = (ns + 999) / 1000;
    tv.tv_sec = (time_t)(us / 1000000);
    tv.tv_usec = (suseconds_t)(us % 1000000);
    return zts_bsd_setsockopt(fd, ZTS_SOL_SOCKET, optname, (void*)&tv, sizeof(tv));
}

/* Convert nanoseconds to a timeval, rounding up to the next microsecond */
static void zts_py_ns_to_timeval(int64_t ns, struct zts_timeval* tv)
{
    int64_t us = (ns + 999) / 1000;
    tv->tv_sec = (long)(us / 1000000);
    tv->tv_usec = (long)(us % 1000000);
}

/* Convert (host, port) for ZTS_AF_INET or (host, port[, flowinfo[, scope_id]])
   for ZTS_AF_INET6 into a socket address. Note: the family is a ZTS_AF_*
   constant, which differs from the host's AF_INET6 on some platforms. */
static int zts_py_tuple_to_sockaddr(int family, PyObject* addr_obj, struct zts_sockaddr* dst_addr, int* addrlen)
{
    char* host_str = NULL;
    int result, port;
    if (! PyTuple_Check(addr_obj)) {
        return ZTS_ERR_ARG;
    }
    if (family == ZTS_AF_INET) {
        struct zts_sockaddr_in* addr = (struct zts_sockaddr_in*)dst_addr;
        if (! PyArg_ParseTuple(addr_obj, "eti:zts_py_tuple_to_sockaddr", "idna", &host_str, &port)) {
            PyErr_Clear();
            return ZTS_ERR_ARG;
        }
        memset(addr, 0, sizeof(*addr));
        result = zts_inet_pton(ZTS_AF_INET, host_str, &(addr->sin_addr));
        PyMem_Free(host_str);
        if (port < 0 || port > 0xFFFF || result != 1) {
            return ZTS_ERR_ARG;
        }
        addr->sin_len = sizeof(*addr);
        addr->sin_family = ZTS_AF_INET;
        addr->sin_port = lwip_htons((unsigned short)port);
        *addrlen = sizeof(*addr);
        return ZTS_ERR_OK;
    }
    if (family == ZTS_AF_INET6) {
        struct zts_sockaddr_in6* addr = (struct zts_sockaddr_in6*)dst_addr;
        unsigned int flowinfo = 0, scope_id = 0;
        if (! PyArg_ParseTuple(
                addr_obj,
                "eti|II:zts_py_tuple_to_sockaddr",
                "idna",
                &host_str,
                &port,
                &flowinfo,
                &scope_id)) {
            PyErr_Clear();
            return ZTS_ERR_ARG;
        }
        memset(addr, 0, sizeof(*addr));
        result = zts_inet_pton(ZTS_AF_INET6, host_str, &(addr->sin6_addr));
        PyMem_Free(host_str);
        if (port < 0 || port > 0xFFFF || result != 1) {
            return ZTS_ERR_ARG;
        }
        addr->sin6_len = sizeof(*addr);
        addr->sin6_family = ZTS_AF_INET6;
        addr->sin6_port = lwip_htons((unsigned short)port);
        addr->sin6_flowinfo = lwip_htonl(flowinfo);
        addr->sin6_scope_id = scope_id;
        *addrlen = sizeof(*addr);
        return ZTS_ERR_OK;
    }
    return ZTS_ERR_ARG;
}

/* (host, port) for IPv4, (host, port, flowinfo, scope_id) for IPv6, like the
   standard socket module. None for unknown families. */
static PyObject* zts_py_sockaddr_to_tuple(const struct zts_sockaddr_storage* ss)
{
    char ipstr[ZTS_INET6_ADDRSTRLEN] = { 0 };
    if (ss->ss_family == ZTS_AF_INET6) {
        const struct zts_sockaddr_in6* in6 = (const struct zts_sockaddr_in6*)ss;
        zts_inet_ntop(ZTS_AF_INET6, &(in6->sin6_addr), ipstr, sizeof(ipstr));
        return Py_BuildValue(
            "(siII)",
            ipstr,
            (int)lwip_ntohs(in6->sin6_port),
            (unsigned int)lwip_ntohl(in6->sin6_flowinfo),
            (unsigned int)in6->sin6_scope_id);
    }
    if (ss->ss_family == ZTS_AF_INET) {
        const struct zts_sockaddr_in* in4 = (const struct zts_sockaddr_in*)ss;
        zts_inet_ntop(ZTS_AF_INET, &(in4->sin_addr), ipstr, sizeof(ipstr));
        return Py_BuildValue("(si)", ipstr, (int)lwip_ntohs(in4->sin_port));
    }
    Py_RETURN_NONE;
}

/* Returns (err, address) */
static PyObject* zts_py_name(int fd, int peer)
{
    struct zts_sockaddr_storage ss;
    memset(&ss, 0, sizeof(ss));
    zts_socklen_t len = sizeof(ss);
    int err = peer ? zts_bsd_getpeername(fd, (struct zts_sockaddr*)&ss, &len)
                   : zts_bsd_getsockname(fd, (struct zts_sockaddr*)&ss, &len);
    if (err < 0) {
        return Py_BuildValue("(iO)", err, Py_None);
    }
    return Py_BuildValue("(iN)", err, zts_py_sockaddr_to_tuple(&ss));
}

PyObject* zts_py_getsockname(int fd)
{
    return zts_py_name(fd, 0);
}

PyObject* zts_py_getpeername(int fd)
{
    return zts_py_name(fd, 1);
}

/* Returns (bytes_read, data, address) */
PyObject* zts_py_recvfrom(int fd, int len, int flags)
{
    if (len < 0) {
        return Py_BuildValue("(iOO)", ZTS_ERR_ARG, Py_None, Py_None);
    }
    PyObject* buf = PyBytes_FromStringAndSize((char*)0, len);
    if (buf == NULL) {
        return NULL;
    }
    struct zts_sockaddr_storage ss;
    memset(&ss, 0, sizeof(ss));
    zts_socklen_t addrlen = sizeof(ss);
    int bytes_read;
    Py_BEGIN_ALLOW_THREADS;
    bytes_read = zts_bsd_recvfrom(fd, PyBytes_AS_STRING(buf), len, flags, (struct zts_sockaddr*)&ss, &addrlen);
    Py_END_ALLOW_THREADS;
    if (bytes_read < 0) {
        Py_DECREF(buf);
        return Py_BuildValue("(iOO)", bytes_read, Py_None, Py_None);
    }
    if (bytes_read != len && _PyBytes_Resize(&buf, bytes_read) < 0) {
        return NULL;
    }
    return Py_BuildValue("(iNN)", bytes_read, buf, zts_py_sockaddr_to_tuple(&ss));
}

int zts_py_sendto(int fd, PyObject* bytes, int flags, int family, PyObject* addr_obj)
{
    struct zts_sockaddr_storage addrbuf;
    int addrlen;
    if (zts_py_tuple_to_sockaddr(family, addr_obj, (struct zts_sockaddr*)&addrbuf, &addrlen) != ZTS_ERR_OK) {
        return ZTS_ERR_ARG;
    }
    Py_buffer output;
    if (PyObject_GetBuffer(bytes, &output, PyBUF_SIMPLE) != 0) {
        PyErr_Clear();
        return ZTS_ERR_ARG;
    }
    int bytes_sent;
    Py_BEGIN_ALLOW_THREADS;
    bytes_sent = zts_bsd_sendto(fd, output.buf, output.len, flags, (struct zts_sockaddr*)&addrbuf, addrlen);
    Py_END_ALLOW_THREADS;
    PyBuffer_Release(&output);
    return bytes_sent;
}

/* Returns (fd, host, port) */
PyObject* zts_py_accept(int fd)
{
    struct zts_sockaddr_storage addrbuf;
    memset(&addrbuf, 0, sizeof(addrbuf));
    zts_socklen_t addrlen = sizeof(addrbuf);
    int err = ZTS_ERR_OK;
    Py_BEGIN_ALLOW_THREADS;
    err = zts_bsd_accept(fd, (struct zts_sockaddr*)&addrbuf, &addrlen);
    Py_END_ALLOW_THREADS;
    char ipstr[ZTS_INET6_ADDRSTRLEN] = { 0 };
    int port = 0;
    if (addrbuf.ss_family == ZTS_AF_INET6) {
        struct zts_sockaddr_in6* in6 = (struct zts_sockaddr_in6*)&addrbuf;
        zts_inet_ntop(ZTS_AF_INET6, &(in6->sin6_addr), ipstr, sizeof(ipstr));
        port = lwip_ntohs(in6->sin6_port);
    }
    else if (addrbuf.ss_family == ZTS_AF_INET) {
        struct zts_sockaddr_in* in4 = (struct zts_sockaddr_in*)&addrbuf;
        zts_inet_ntop(ZTS_AF_INET, &(in4->sin_addr), ipstr, sizeof(ipstr));
        port = lwip_ntohs(in4->sin_port);
    }
    return Py_BuildValue("(isi)", err, ipstr, port);
}

int zts_py_bind(int fd, int family, int type, PyObject* addr_obj)
{
    struct zts_sockaddr_storage addrbuf;
    int addrlen;
    int err;
    if (zts_py_tuple_to_sockaddr(family, addr_obj, (struct zts_sockaddr*)&addrbuf, &addrlen) != ZTS_ERR_OK) {
        return ZTS_ERR_ARG;
    }
    Py_BEGIN_ALLOW_THREADS;
    err = zts_bsd_bind(fd, (struct zts_sockaddr*)&addrbuf, addrlen);
    Py_END_ALLOW_THREADS;
    return err;
}

int zts_py_connect(int fd, int family, int type, PyObject* addr_obj)
{
    struct zts_sockaddr_storage addrbuf;
    int addrlen;
    int err;
    if (zts_py_tuple_to_sockaddr(family, addr_obj, (struct zts_sockaddr*)&addrbuf, &addrlen) != ZTS_ERR_OK) {
        return ZTS_ERR_ARG;
    }
    Py_BEGIN_ALLOW_THREADS;
    err = zts_bsd_connect(fd, (struct zts_sockaddr*)&addrbuf, addrlen);
    Py_END_ALLOW_THREADS;
    return err;
}

PyObject* zts_py_recv(int fd, int len, int flags)
{
    PyObject* buf;
    int bytes_read;

    buf = PyBytes_FromStringAndSize((char*)0, len);
    if (buf == NULL) {
        return NULL;
    }

    Py_BEGIN_ALLOW_THREADS;
    bytes_read = zts_bsd_recv(fd, PyBytes_AS_STRING(buf), len, flags);
    Py_END_ALLOW_THREADS;

    if (bytes_read < 0) {
        Py_DECREF(buf);
        return Py_BuildValue("(iO)", bytes_read, Py_None);
    }
    if (bytes_read != len && _PyBytes_Resize(&buf, bytes_read) < 0) {
        return NULL;
    }
    // "N" steals the reference to buf
    return Py_BuildValue("(iN)", bytes_read, buf);
}

int zts_py_send(int fd, PyObject* buf, int flags)
{
    Py_buffer output;
    int bytes_sent;

    if (PyObject_GetBuffer(buf, &output, PyBUF_SIMPLE) != 0) {
        return 0;
    }
    Py_BEGIN_ALLOW_THREADS;
    bytes_sent = zts_bsd_send(fd, output.buf, output.len, flags);
    Py_END_ALLOW_THREADS;
    PyBuffer_Release(&output);

    return bytes_sent;
}

int zts_py_sendall(int fd, PyObject* bytes, int flags)
{
    int res;
    Py_buffer output;

    char *buf;
    int bytes_left;

    int has_timeout;
    int deadline_initialized = 0;

    int64_t timeout;    // Timeout duration (ns)
    int64_t interval;   // Time remaining until deadline (ns)
    int64_t deadline = 0;   // Monotonic clock deadline for timeout (ns)

    if (PyObject_GetBuffer(bytes, &output, PyBUF_SIMPLE) != 0) {
        // BufferError has been raised. No need to set our own error.
        res = ZTS_ERR_OK;
        goto done;
    }

    buf = (char *) output.buf;
    bytes_left = output.len;

    res = zts_py_get_timeout_ns(fd, ZTS_SO_SNDTIMEO, &timeout);
    if (res < 0)
        goto done;

    interval = timeout;
    has_timeout = (interval > 0);

    /* Call zts_bsd_send() until no more bytes left to send in the buffer.
    Keep track of remaining time until timeout and exit with ZTS_ETIMEDOUT if timeout exceeded.
    Check signals between calls to send() to prevent undue blocking.*/
    do {
        if (has_timeout) {
            if (deadline_initialized) {
                interval = deadline - zts_py_monotonic_ns();
            } else {
                deadline_initialized = 1;
                deadline = zts_py_monotonic_ns() + timeout;
            }

            if (interval <= 0) {
                zts_errno = ZTS_ETIMEDOUT;
                res = ZTS_ERR_SOCKET;
                goto done;
            }
        }

        Py_BEGIN_ALLOW_THREADS;
        res = zts_bsd_send(fd, buf, bytes_left, flags);
        Py_END_ALLOW_THREADS;
        if (res < 0)
            goto done;

        int bytes_sent = res;
        assert(bytes_sent > 0);

        buf += bytes_sent;  // Advance pointer
        bytes_left -= bytes_sent;

        if (PyErr_CheckSignals())  // Handle interrupts, etc.
            goto done;

    } while (bytes_left > 0);

    res = ZTS_ERR_OK;  // Success

done:
    if (output.obj != NULL)
        PyBuffer_Release(&output);
    return res;
}

int zts_py_close(int fd)
{
    int err;
    Py_BEGIN_ALLOW_THREADS;
    err = zts_bsd_close(fd);
    Py_END_ALLOW_THREADS;
    return err;
}

PyObject* zts_py_addr_get_str(uint64_t net_id, int family)
{
    char addr_str[ZTS_IP_MAX_STR_LEN] = { 0 };
    if (zts_addr_get_str(net_id, family, addr_str, ZTS_IP_MAX_STR_LEN) < 0) {
        PyErr_SetString(PyExc_Warning, "No address of the given type has been assigned by the network");
        return NULL;
    }
    PyObject* t = PyUnicode_FromString(addr_str);
    return t;
}

/* list of Python objects and their file descriptor */
typedef struct {
    PyObject* obj; /* owned reference */
    int fd;
    int sentinel; /* -1 == sentinel */
} pylist;

void reap_obj(pylist fd2obj[ZTS_FD_SETSIZE + 1])
{
    unsigned int i;
    for (i = 0; i < (unsigned int)ZTS_FD_SETSIZE + 1 && fd2obj[i].sentinel >= 0; i++) {
        Py_CLEAR(fd2obj[i].obj);
    }
    fd2obj[0].sentinel = -1;
}

/* returns NULL and sets the Python exception if an error occurred */
PyObject* set2list(zts_fd_set* set, pylist fd2obj[ZTS_FD_SETSIZE + 1])
{
    int i, j, count = 0;
    PyObject *list, *o;
    int fd;

    for (j = 0; fd2obj[j].sentinel >= 0; j++) {
        if (ZTS_FD_ISSET(fd2obj[j].fd, set)) {
            count++;
        }
    }
    list = PyList_New(count);
    if (! list) {
        return NULL;
    }

    i = 0;
    for (j = 0; fd2obj[j].sentinel >= 0; j++) {
        fd = fd2obj[j].fd;
        if (ZTS_FD_ISSET(fd, set)) {
            o = fd2obj[j].obj;
            fd2obj[j].obj = NULL;
            /* transfer ownership */
            if (PyList_SetItem(list, i, o) < 0) {
                goto finally;
            }
            i++;
        }
    }
    return list;
finally:
    Py_DECREF(list);
    return NULL;
}

/* returns -1 and sets the Python exception if an error occurred, otherwise
   returns a number >= 0
*/
int seq2set(PyObject* seq, zts_fd_set* set, pylist fd2obj[FD_SETSIZE + 1])
{
    int max = -1;
    unsigned int index = 0;
    Py_ssize_t i;
    PyObject* fast_seq = NULL;
    PyObject* o = NULL;

    fd2obj[0].obj = (PyObject*)0; /* set list to zero size */
    ZTS_FD_ZERO(set);

    fast_seq = PySequence_Fast(seq, "arguments 1-3 must be sequences");
    if (! fast_seq) {
        return -1;
    }

    for (i = 0; i < PySequence_Fast_GET_SIZE(fast_seq); i++) {
        int v;

        /* any intervening fileno() calls could decr this refcnt */
        if (! (o = PySequence_Fast_GET_ITEM(fast_seq, i))) {
            goto finally;
        }

        Py_INCREF(o);
        v = PyObject_AsFileDescriptor(o);
        if (v == -1) {
            goto finally;
        }

#if defined(_MSC_VER)
        max = 0; /* not used for Win32 */
#else            /* !_MSC_VER */
        if (v < 0 || v >= ZTS_FD_SETSIZE) {
            PyErr_SetString(PyExc_ValueError, "filedescriptor out of range in select()");
            goto finally;
        }
        if (v > max) {
            max = v;
        }
#endif           /* _MSC_VER */
        ZTS_FD_SET(v, set);

        /* add object and its file descriptor to the list */
        if (index >= (unsigned int)FD_SETSIZE) {
            PyErr_SetString(PyExc_ValueError, "too many file descriptors in select()");
            goto finally;
        }
        fd2obj[index].obj = o;
        fd2obj[index].fd = v;
        fd2obj[index].sentinel = 0;
        fd2obj[++index].sentinel = -1;
    }
    Py_DECREF(fast_seq);
    return max + 1;

finally:
    Py_XDECREF(o);
    Py_DECREF(fast_seq);
    return -1;
}

PyObject* zts_py_select(PyObject* module, PyObject* rlist, PyObject* wlist, PyObject* xlist, PyObject* timeout_obj)
{
    pylist rfd2obj[FD_SETSIZE + 1];
    pylist wfd2obj[FD_SETSIZE + 1];
    pylist efd2obj[FD_SETSIZE + 1];
    PyObject* ret = NULL;
    zts_fd_set ifdset, ofdset, efdset;
    struct zts_timeval tv, *tvp;
    int imax, omax, emax, max;
    int n;
    int64_t timeout = 0, deadline = 0;

    if (timeout_obj == Py_None) {
        tvp = (struct zts_timeval*)NULL;
    }
    else {
        if (zts_py_timeout_from_object(timeout_obj, &timeout) < 0) {
            return NULL;
        }
        zts_py_ns_to_timeval(timeout, &tv);
        tvp = &tv;
    }
    /* Convert iterables to zts_fd_sets, and get maximum fd number
     * propagates the Python exception set in seq2set()
     */
    rfd2obj[0].sentinel = -1;
    wfd2obj[0].sentinel = -1;
    efd2obj[0].sentinel = -1;
    if ((imax = seq2set(rlist, &ifdset, rfd2obj)) < 0) {
        goto finally;
    }
    if ((omax = seq2set(wlist, &ofdset, wfd2obj)) < 0) {
        goto finally;
    }
    if ((emax = seq2set(xlist, &efdset, efd2obj)) < 0) {
        goto finally;
    }

    max = imax;
    if (omax > max) {
        max = omax;
    }
    if (emax > max) {
        max = emax;
    }
    if (tvp) {
        deadline = zts_py_monotonic_ns() + timeout;
    }

    do {
        int err = 0;
        Py_BEGIN_ALLOW_THREADS;
        n = zts_bsd_select(max, &ifdset, &ofdset, &efdset, tvp);
        err = (n < 0) ? zts_errno : 0;
        Py_END_ALLOW_THREADS;

        if (err != ZTS_EINTR) {
            if (n < 0) {
                errno = err;
            }
            break;
        }

        /* select() was interrupted by a signal */
        if (PyErr_CheckSignals()) {
            goto finally;
        }

        if (tvp) {
            timeout = deadline - zts_py_monotonic_ns();
            if (timeout < 0) {
                /* bpo-35310: lists were unmodified -- clear them explicitly */
                ZTS_FD_ZERO(&ifdset);
                ZTS_FD_ZERO(&ofdset);
                ZTS_FD_ZERO(&efdset);
                n = 0;
                break;
            }
            zts_py_ns_to_timeval(timeout, &tv);
            /* retry select() with the recomputed timeout */
        }
    } while (1);

#ifdef MS_WINDOWS
    if (n == SOCKET_ERROR) {
        PyErr_SetExcFromWindowsErr(PyExc_OSError, WSAGetLastError());
    }
#else
    if (n < 0) {
        PyErr_SetFromErrno(PyExc_OSError);
    }
#endif
    else {
        /* any of these three calls can raise an exception.  it's more
           convenient to test for this after all three calls... but
           is that acceptable?
        */
        rlist = set2list(&ifdset, rfd2obj);
        wlist = set2list(&ofdset, wfd2obj);
        xlist = set2list(&efdset, efd2obj);
        if (PyErr_Occurred()) {
            ret = NULL;
        }
        else {
            ret = PyTuple_Pack(3, rlist, wlist, xlist);
        }
        Py_XDECREF(rlist);
        Py_XDECREF(wlist);
        Py_XDECREF(xlist);
    }

finally:
    reap_obj(rfd2obj);
    reap_obj(wfd2obj);
    reap_obj(efd2obj);
    return ret;
}

int zts_py_setsockopt(int fd, PyObject* args)
{
    int level;
    int optname;
    int res;
    Py_buffer optval;
    int flag;
    unsigned int optlen;
    PyObject* none;

    // setsockopt(level, opt, flag)
    if (PyArg_ParseTuple(args, "iii:setsockopt", &level, &optname, &flag)) {
        res = zts_bsd_setsockopt(fd, level, optname, (char*)&flag, sizeof flag);
        goto done;
    }

    PyErr_Clear();
    // setsockopt(level, opt, None, flag)
    if (PyArg_ParseTuple(args, "iiO!I:setsockopt", &level, &optname, Py_TYPE(Py_None), &none, &optlen)) {
        assert(sizeof(socklen_t) >= sizeof(unsigned int));
        res = zts_bsd_setsockopt(fd, level, optname, NULL, (socklen_t)optlen);
        goto done;
    }

    PyErr_Clear();
    // setsockopt(level, opt, buffer)
    if (! PyArg_ParseTuple(args, "iiy*:setsockopt", &level, &optname, &optval)) {
        return (int)NULL;
    }

#ifdef MS_WINDOWS
    if (optval.len > INT_MAX) {
        PyBuffer_Release(&optval);
        PyErr_Format(PyExc_OverflowError, "socket option is larger than %i bytes", INT_MAX);
        return (int)NULL;
    }
    res = zts_bsd_setsockopt(fd, level, optname, optval.buf, (int)optval.len);
#else
    res = zts_bsd_setsockopt(fd, level, optname, optval.buf, optval.len);
#endif
    PyBuffer_Release(&optval);

done:
    return res;
}

int zts_py_settimeout(int fd, PyObject* value)
{
    int res;
    int64_t timeout = 0;

    // None: blocking mode without timeout
    if (value != Py_None) {
        if (zts_py_timeout_from_object(value, &timeout) < 0) {
            // Report an argument error, not a Python exception, to the caller
            PyErr_Clear();
            return ZTS_ERR_ARG;
        }
    }

    // Zero: non-blocking mode. Otherwise operations block for up to the
    // timeout (SO_RCVTIMEO/SO_SNDTIMEO are ignored by non-blocking sockets)
    res = zts_set_blocking(fd, value == Py_None || timeout > 0);
    if (res < 0) {
        return res;
    }
    res = zts_py_set_timeout_ns(fd, ZTS_SO_SNDTIMEO, timeout);
    if (res < 0) {
        return res;
    }
    return zts_py_set_timeout_ns(fd, ZTS_SO_RCVTIMEO, timeout);
}

PyObject* zts_py_gettimeout(int fd)
{
    int64_t timeout = 0;
    int res = zts_get_blocking(fd);

    // Non-blocking mode: (0, 0.0)
    if (res == 0) {
        return Py_BuildValue("(id)", 0, 0.0);
    }
    if (res > 0) {
        // Send and recv timeouts are always set together
        res = zts_py_get_timeout_ns(fd, ZTS_SO_RCVTIMEO, &timeout);
    }
    // Error: (err, None)
    if (res < 0) {
        return Py_BuildValue("(iO)", res, Py_None);
    }
    // Blocking mode without timeout: (0, None)
    if (timeout == 0) {
        return Py_BuildValue("(iO)", 0, Py_None);
    }
    // Blocking mode with timeout: (0, timeout in seconds)
    return Py_BuildValue("(id)", 0, (double)timeout / 1e9);
}

PyObject* zts_py_getsockopt(int fd, PyObject* args)
{
    int level;
    int optname;
    int res;
    PyObject* buf;
    socklen_t buflen = 0;
    int flag = 0;
    socklen_t flagsize;

    if (! PyArg_ParseTuple(args, "ii|i:getsockopt", &level, &optname, &buflen)) {
        return NULL;
    }
    if (buflen == 0) {
        flagsize = sizeof flag;
        res = zts_bsd_getsockopt(fd, level, optname, (void*)&flag, &flagsize);
        if (res < 0) {
            return set_error();
        }
        return PyLong_FromLong(flag);
    }
    if (buflen <= 0 || buflen > 1024) {
        PyErr_SetString(PyExc_OSError, "getsockopt buflen out of range");
        return NULL;
    }
    buf = PyBytes_FromStringAndSize((char*)NULL, buflen);
    if (buf == NULL) {
        return NULL;
    }
    res = zts_bsd_getsockopt(fd, level, optname, (void*)PyBytes_AS_STRING(buf), &buflen);
    if (res < 0) {
        Py_DECREF(buf);
        return set_error();
    }
    _PyBytes_Resize(&buf, buflen);
    return buf;
}

PyObject* zts_py_fcntl(int fd, int code, PyObject* arg)
{
    unsigned int int_arg = 0;
    int ret;

    if (arg != NULL) {
        int parse_result;
        PyErr_Clear();
        parse_result = PyArg_Parse(
            arg,
            "I;fcntl requires a file or file descriptor,"
            " an integer and optionally a third integer",
            &int_arg);
        if (! parse_result) {
            return NULL;
        }
    }
    do {
        Py_BEGIN_ALLOW_THREADS;
        ret = zts_bsd_fcntl(fd, code, (int)int_arg);
        Py_END_ALLOW_THREADS;
    } while (ret == -1 && zts_errno == ZTS_EINTR);
    if (ret < 0) {
        return set_error();
    }
    return PyLong_FromLong((long)ret);
}

PyObject* zts_py_ioctl(int fd, unsigned int code, PyObject* ob_arg, int mutate_arg)
{
#define IOCTL_BUFSZ 1024
    int arg = 0;
    int ret;
    Py_buffer pstr;
    char* str;
    Py_ssize_t len;
    char buf[IOCTL_BUFSZ + 1]; /* argument plus NUL byte */

    if (ob_arg != NULL) {
        if (PyArg_Parse(ob_arg, "w*:ioctl", &pstr)) {
            char* arg;
            str = (char*)pstr.buf;
            len = pstr.len;

            if (mutate_arg) {
                if (len <= IOCTL_BUFSZ) {
                    memcpy(buf, str, len);
                    buf[len] = '\0';
                    arg = buf;
                }
                else {
                    arg = str;
                }
            }
            else {
                if (len > IOCTL_BUFSZ) {
                    PyBuffer_Release(&pstr);
                    PyErr_SetString(PyExc_ValueError, "ioctl string arg too long");
                    return NULL;
                }
                else {
                    memcpy(buf, str, len);
                    buf[len] = '\0';
                    arg = buf;
                }
            }
            if (buf == arg) {
                Py_BEGIN_ALLOW_THREADS;
                /* think array.resize() */
                ret = zts_bsd_ioctl(fd, code, arg);
                Py_END_ALLOW_THREADS;
            }
            else {
                ret = zts_bsd_ioctl(fd, code, arg);
            }
            if (mutate_arg && (len <= IOCTL_BUFSZ)) {
                memcpy(str, buf, len);
            }
            PyBuffer_Release(&pstr); /* No further access to str below this point */
            if (ret < 0) {
                PyErr_SetFromErrno(PyExc_OSError);
                return NULL;
            }
            if (mutate_arg) {
                return PyLong_FromLong(ret);
            }
            else {
                return PyBytes_FromStringAndSize(buf, len);
            }
        }

        PyErr_Clear();
        if (PyArg_Parse(ob_arg, "s*:ioctl", &pstr)) {
            str = (char*)pstr.buf;
            len = pstr.len;
            if (len > IOCTL_BUFSZ) {
                PyBuffer_Release(&pstr);
                PyErr_SetString(PyExc_ValueError, "ioctl string arg too long");
                return NULL;
            }
            memcpy(buf, str, len);
            buf[len] = '\0';
            Py_BEGIN_ALLOW_THREADS;
            ret = zts_bsd_ioctl(fd, code, buf);
            Py_END_ALLOW_THREADS;
            if (ret < 0) {
                PyBuffer_Release(&pstr);
                PyErr_SetFromErrno(PyExc_OSError);
                return NULL;
            }
            PyBuffer_Release(&pstr);
            return PyBytes_FromStringAndSize(buf, len);
        }

        PyErr_Clear();
        if (! PyArg_Parse(
                ob_arg,
                "i;ioctl requires a file or file descriptor,"
                " an integer and optionally an integer or buffer argument",
                &arg)) {
            return NULL;
        }
        // Fall-through to outside the 'if' statement.
    }
    // TODO: Double check that &arg is correct
    Py_BEGIN_ALLOW_THREADS;
    ret = zts_bsd_ioctl(fd, code, &arg);
    Py_END_ALLOW_THREADS;
    if (ret < 0) {
        PyErr_SetFromErrno(PyExc_OSError);
        return NULL;
    }
    return PyLong_FromLong((long)ret);
#undef IOCTL_BUFSZ
}

#endif   // ZTS_ENABLE_PYTHON
