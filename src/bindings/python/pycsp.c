/*
Cubesat Space Protocol - A small network-layer protocol designed for Cubesats
Copyright (C) 2012 GomSpace ApS (http://www.gomspace.com)
Copyright (C) 2012 AAUSAT3 Project (http://aausat3.space.aau.dk) 

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 2.1 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/

#include <Python.h>
#include <csp/csp.h>
#include <csp/csp_cmp.h>
#include <csp/crypto/csp_xtea.h>
#include <csp/interfaces/csp_if_zmqhub.h>
#include <csp/interfaces/csp_if_kiss.h>
#include <csp/drivers/usart.h>
#include <csp/drivers/can_socketcan.h>
#include <csp/csp_endian.h>

static PyObject *GenericError = NULL;

static int is_capsule_of_type(PyObject* capsule, const char* expected_type) {
    if (capsule == 0) {
        return 0;
    }
    const char* capsule_name = PyCapsule_GetName(capsule);
    if (strcmp(capsule_name, expected_type) != 0) {
        PyErr_Format(PyExc_TypeError,
                     "capsule contains unexpected type, expected=%s, got=%s",
                     expected_type, capsule_name); // TypeError is thrown
        return 0;
    }
    return 1;
}

static csp_packet_t * get_obj_as_packet(PyObject* obj) {
    csp_packet_t * packet = NULL;
    if (is_capsule_of_type(obj, "csp_packet_t")) {
        packet = PyCapsule_GetPointer(obj, "csp_packet_t");
        if (packet == NULL) {
            PyErr_Format(PyExc_TypeError,
                         "capsule contains csp_packet_t NULL pointer");
        }
    }
    return packet;
}

static csp_conn_t * get_obj_as_conn(PyObject* obj) {
    csp_conn_t * conn = NULL;
    if (is_capsule_of_type(obj, "csp_conn_t")) {
        conn = PyCapsule_GetPointer(obj, "csp_conn_t");
        if (conn == NULL) {
            PyErr_Format(PyExc_TypeError,
                         "capsule contains csp_conn_t NULL pointer");
        }
    }
    return conn;
}

static csp_socket_t * get_obj_as_socket(PyObject* obj) {
    csp_socket_t * socket = NULL;
    if (is_capsule_of_type(obj, "csp_socket_t")) {
        socket = PyCapsule_GetPointer(obj, "csp_socket_t");
        if (socket == NULL) {
            PyErr_Format(PyExc_TypeError,
                         "capsule contains csp_socket_t NULL pointer");
        }
    }
    return socket;
}

static PyObject* PyErr_GenericError(const char * message, int error) {
    PyErr_Format(GenericError, "%s, error: %d", message, error); // should set error as member
    return NULL;
}

static int CSP_POINTER_HAS_BEEN_FREED = 0; // used to indicate pointer has been freed, because a NULL pointer can't be set.

static void pycsp_free_csp_buffer(PyObject *obj) {
    printf("%s: %p\r\n", __FUNCTION__, obj);
    csp_packet_t * packet = get_obj_as_packet(obj);
    if (packet && (packet != (csp_packet_t*)&CSP_POINTER_HAS_BEEN_FREED)) {
        csp_buffer_free(packet);
    }
    PyCapsule_SetPointer(obj, &CSP_POINTER_HAS_BEEN_FREED);
}

static PyObject* pycsp_service_handler(PyObject *self, PyObject *args) {
    PyObject* conn_capsule;
    PyObject* packet_capsule;
    if (!PyArg_ParseTuple(args, "OO", &conn_capsule, &packet_capsule)) {
        return NULL; // TypeError is thrown
    }
    csp_conn_t* conn = get_obj_as_conn(conn_capsule);
    if (conn == NULL) {
        return NULL;
    }
    csp_packet_t* packet = get_obj_as_packet(packet_capsule);
    if (packet == NULL) {
        return NULL;
    }

    csp_service_handler(conn, packet);
    PyCapsule_SetPointer(packet_capsule, &CSP_POINTER_HAS_BEEN_FREED);
    Py_RETURN_NONE;
}

static PyObject* pycsp_init(PyObject *self, PyObject *args) {

    csp_conf_t conf;
    csp_conf_get_defaults(&conf);

    if (!PyArg_ParseTuple(args, "bsssHH", &conf.address, &conf.hostname, &conf.model, &conf.revision, &conf.buffers, &conf.buffer_data_size)) {
        return NULL; // TypeError is thrown
    }

    int res = csp_init(&conf);
    if (res != CSP_ERR_NONE) {
        return PyErr_GenericError("csp_init()", res);
    }

    Py_RETURN_NONE;
}

static PyObject* pycsp_get_hostname(PyObject *self, PyObject *args) {
    return Py_BuildValue("s", csp_get_conf()->hostname);
}

static PyObject* pycsp_get_model(PyObject *self, PyObject *args) {
    return Py_BuildValue("s", csp_get_conf()->model);
}

static PyObject* pycsp_get_revision(PyObject *self, PyObject *args) {
    return Py_BuildValue("s", csp_get_conf()->revision);
}

static PyObject* pycsp_socket(PyObject *self, PyObject *args) {
    uint32_t opts = CSP_SO_NONE;
    if (!PyArg_ParseTuple(args, "|I", &opts)) {
        return NULL; // TypeError is thrown
    }

    csp_socket_t * socket = csp_socket(opts);
    if (socket == NULL) {
        return PyErr_GenericError("csp_socket() - no free sockets/connections", CSP_ERR_NOBUFS);
    }
    return PyCapsule_New(socket, "csp_socket_t", NULL);
}

static PyObject* pycsp_accept(PyObject *self, PyObject *args) {
    PyObject* socket_capsule;
    uint32_t timeout = CSP_MAX_TIMEOUT;
    if (!PyArg_ParseTuple(args, "O|I", &socket_capsule, &timeout)) {
        return NULL; // TypeError is thrown
    }
    csp_socket_t* socket = get_obj_as_socket(socket_capsule);
    if (socket == NULL) {
        return NULL;
    }
    csp_conn_t* conn;
    Py_BEGIN_ALLOW_THREADS;
    conn = csp_accept(socket, timeout);
    Py_END_ALLOW_THREADS;
    if (conn == NULL) {
        Py_RETURN_NONE; // timeout -> None
    }

    return PyCapsule_New(conn, "csp_conn_t", NULL);
}

static PyObject* pycsp_read(PyObject *self, PyObject *args) {
    PyObject* conn_capsule;
    uint32_t timeout = 500;
    if (!PyArg_ParseTuple(args, "O|I", &conn_capsule, &timeout)) {
        return NULL; // TypeError is thrown
    }
    csp_conn_t* conn = get_obj_as_conn(conn_capsule);
    if (conn == NULL) {
        return NULL;
    }
    csp_packet_t* packet;
    Py_BEGIN_ALLOW_THREADS;
    packet = csp_read(conn, timeout);
    Py_END_ALLOW_THREADS;
    if (packet == NULL) {
        Py_RETURN_NONE; // timeout -> None
    }

    return PyCapsule_New(packet, "csp_packet_t", pycsp_free_csp_buffer);
}

static PyObject* pycsp_send(PyObject *self, PyObject *args) {
    PyObject* conn_capsule;
    PyObject* packet_capsule;
    uint32_t timeout = 1000;
    if (!PyArg_ParseTuple(args, "OO|I", &conn_capsule, &packet_capsule, &timeout)) {
        return NULL; // TypeError is thrown
    }
    csp_conn_t* conn = get_obj_as_conn(conn_capsule);
    if (conn == NULL) {
        return NULL;
    }
    csp_packet_t* packet = get_obj_as_packet(packet_capsule);
    if (packet == NULL) {
        return NULL;
    }

    int res;
    Py_BEGIN_ALLOW_THREADS;
    res = csp_send(conn, packet, timeout);
    Py_END_ALLOW_THREADS;
    if (res != CSP_ERR_NONE) {
        return PyErr_GenericError("csp_send()", res);
    }

    return Py_BuildValue("i", res);
}

static PyObject* pycsp_transaction(PyObject *self, PyObject *args) {
    uint8_t prio;
    uint8_t dest;
    uint8_t port;
    uint32_t timeout;
    Py_buffer inbuf;
    Py_buffer outbuf;
    if (!PyArg_ParseTuple(args, "bbbIw*w*", &prio, &dest, &port, &timeout, &outbuf, &inbuf)) {
        return NULL; // TypeError is thrown
    }

    int res;
    Py_BEGIN_ALLOW_THREADS;
    res = csp_transaction(prio, dest, port, timeout, outbuf.buf, outbuf.len, inbuf.buf, inbuf.len);
    Py_END_ALLOW_THREADS;
    if (res < 1) {
        return PyErr_GenericError("csp_transaction()", res);
    }

    return Py_BuildValue("i", res);
}

static PyObject* pycsp_sendto(PyObject *self, PyObject *args) {
    uint8_t prio;
    uint8_t dest;
    uint8_t dport;
    uint8_t src_port;
    uint32_t opts;
    PyObject* packet_capsule;
    uint32_t timeout;
    if (!PyArg_ParseTuple(args, "bbbbIOI", &prio, &dest, &dport, &src_port, &opts, &packet_capsule, &timeout)) {
        Py_RETURN_NONE;
    }
    csp_packet_t* packet = get_obj_as_packet(packet_capsule);
    if (packet == NULL) {
        return NULL;
    }

    int res;
    Py_BEGIN_ALLOW_THREADS;
    res = csp_sendto(prio, dest, dport, src_port, opts, packet, timeout);
    Py_END_ALLOW_THREADS;
    if (res != CSP_ERR_NONE) {
        return PyErr_GenericError("csp_sendto()", res);
    }

    return Py_BuildValue("i", res);
}

static PyObject* pycsp_sendto_reply(PyObject *self, PyObject *args) {
    PyObject* request_packet_capsule;
    PyObject* reply_packet_capsule;
    uint32_t opts = CSP_O_NONE;
    uint32_t timeout = 1000;
    if (!PyArg_ParseTuple(args, "OO|II", &request_packet_capsule, &reply_packet_capsule, &opts, &timeout)) {
        return NULL; // TypeError is thrown
    }
    csp_packet_t* request = get_obj_as_packet(request_packet_capsule);
    if (request == NULL) {
        return NULL;
    }
    csp_packet_t* reply = get_obj_as_packet(reply_packet_capsule);
    if (reply == NULL) {
        return NULL;
    }

    int res;
    Py_BEGIN_ALLOW_THREADS;
    res = csp_sendto_reply(request, reply, opts, timeout);
    Py_END_ALLOW_THREADS;
    if (res != CSP_ERR_NONE) {
        return PyErr_GenericError("csp_sendto_reply()", res);
    } else {
        PyCapsule_SetPointer(reply_packet_capsule, &CSP_POINTER_HAS_BEEN_FREED);
    }

    return Py_BuildValue("i", res);
}

static PyObject* pycsp_connect(PyObject *self, PyObject *args) {
    uint8_t prio;
    uint8_t dest;
    uint8_t dport;
    uint32_t timeout;
    uint32_t opts;
    if (!PyArg_ParseTuple(args, "bbbII", &prio, &dest, &dport, &timeout, &opts)) {
        return NULL; // TypeError is thrown
    }

    csp_conn_t *conn;
    Py_BEGIN_ALLOW_THREADS;
    conn = csp_connect(prio, dest, dport, timeout, opts);
    Py_END_ALLOW_THREADS;
    if (conn == NULL) {
        return PyErr_GenericError("csp_connect() timeout or failed", CSP_ERR_TIMEDOUT);
    }

    return PyCapsule_New(conn, "csp_conn_t", NULL);
}

/*
 * int csp_close(csp_conn_t *conn);
 */
static PyObject* pycsp_close(PyObject *self, PyObject *conn_capsule) {
    if (!is_capsule_of_type(conn_capsule, "csp_conn_t")) {
        return NULL; // TypeError is thrown
    }

    void *conn = PyCapsule_GetPointer(conn_capsule, "csp_conn_t");
    return Py_BuildValue("i", csp_close((csp_conn_t*)conn));
}

/*
 * int csp_conn_dport(csp_conn_t *conn);
 */
static PyObject* pycsp_conn_dport(PyObject *self, PyObject *conn_capsule) {
    if (!is_capsule_of_type(conn_capsule, "csp_conn_t")) {
        return NULL; // TypeError is thrown
    }

    void* conn = PyCapsule_GetPointer(conn_capsule, "csp_conn_t");
    return Py_BuildValue("i", csp_conn_dport((csp_conn_t*)conn));
}

/*
 * int csp_conn_sport(csp_conn_t *conn);
 */
static PyObject* pycsp_conn_sport(PyObject *self, PyObject *conn_capsule) {
    if (!is_capsule_of_type(conn_capsule, "csp_conn_t")) {
        return NULL; // TypeError is thrown
    }

    void* conn = PyCapsule_GetPointer(conn_capsule, "csp_conn_t");
    return Py_BuildValue("i", csp_conn_sport((csp_conn_t*)conn));
}

/* int csp_conn_dst(csp_conn_t *conn); */
static PyObject* pycsp_conn_dst(PyObject *self, PyObject *conn_capsule) {
    if (!is_capsule_of_type(conn_capsule, "csp_conn_t")) {
        return NULL; // TypeError is thrown
    }

    void* conn = PyCapsule_GetPointer(conn_capsule, "csp_conn_t");
    return Py_BuildValue("i", csp_conn_dst((csp_conn_t*)conn));
}

/*
 * int csp_conn_src(csp_conn_t *conn);
 */
static PyObject* pycsp_conn_src(PyObject *self, PyObject *conn_capsule) {
    if (!is_capsule_of_type(conn_capsule, "csp_conn_t")) {
        return NULL; // TypeError is thrown
    }

    void* conn = PyCapsule_GetPointer(conn_capsule, "csp_conn_t");
    return Py_BuildValue("i", csp_conn_src((csp_conn_t*)conn));
}

/* int csp_listen(csp_socket_t *socket, size_t conn_queue_length); */
static PyObject* pycsp_listen(PyObject *self, PyObject *args) {
    PyObject* socket_capsule;
    size_t conn_queue_len = 10;
    if (!PyArg_ParseTuple(args, "O|n", &socket_capsule, &conn_queue_len)) {
        return NULL; // TypeError is thrown
    }

    if (!is_capsule_of_type(socket_capsule, "csp_socket_t")) {
        return NULL; // TypeError is thrown
    }

    void* sock = PyCapsule_GetPointer(socket_capsule, "csp_socket_t");
    return Py_BuildValue("i", csp_listen((csp_socket_t*)sock, conn_queue_len));
}

/* int csp_bind(csp_socket_t *socket, uint8_t port); */
static PyObject* pycsp_bind(PyObject *self, PyObject *args) {
    PyObject* socket_capsule;
    uint8_t port;
    if (!PyArg_ParseTuple(args, "Ob", &socket_capsule, &port)) {
        return NULL; // TypeError is thrown
    }

    if (!is_capsule_of_type(socket_capsule, "csp_socket_t")) {
        return NULL; // TypeError is thrown
    }

    void* sock = PyCapsule_GetPointer(socket_capsule, "csp_socket_t");
    return Py_BuildValue("i", csp_bind((csp_socket_t*)sock, port));
}

/* int csp_route_start_task(unsigned int task_stack_size, unsigned int priority); */
static PyObject* pycsp_route_start_task(PyObject *self, PyObject *args) {
    unsigned int priority = CSP_PRIO_NORM;
    if (!PyArg_ParseTuple(args, "|I", &priority)) {
        return NULL; // TypeError is thrown
    }

    return Py_BuildValue("i", csp_route_start_task(0, priority));
}

/*
 * int csp_ping(uint8_t node, uint32_t timeout,
 *              unsigned int size, uint8_t conn_options);
 */
static PyObject* pycsp_ping(PyObject *self, PyObject *args) {
    uint8_t node;
    uint32_t timeout = 1000;
    unsigned int size = 10;
    uint8_t conn_options = CSP_O_NONE;
    if (!PyArg_ParseTuple(args, "b|IIb", &node, &timeout, &size, &conn_options)) {
        return NULL; // TypeError is thrown
    }

    int res;
    Py_BEGIN_ALLOW_THREADS;
    res = csp_ping(node, timeout, size, conn_options);
    Py_END_ALLOW_THREADS;

    return Py_BuildValue("i", res);
}

/*
 * void csp_reboot(uint8_t node);
 */
static PyObject* pycsp_reboot(PyObject *self, PyObject *args) {
    uint8_t node;
    if (!PyArg_ParseTuple(args, "b", &node)) {
        return NULL; // TypeError is thrown
    }

    csp_reboot(node);
    Py_RETURN_NONE;
}

/*
 * void csp_shutdown(uint8_t node);
 */
static PyObject* pycsp_shutdown(PyObject *self, PyObject *args) {
    uint8_t node;
    if (!PyArg_ParseTuple(args, "b", &node)) {
        return NULL; // TypeError is thrown
    }

    csp_shutdown(node);
    Py_RETURN_NONE;
}

/*
 * void csp_rdp_set_opt(unsigned int window_size,
 *                      unsigned int conn_timeout_ms,
 *                      unsigned int packet_timeout_ms,
 *                      unsigned int delayed_acks,
 *                      unsigned int ack_timeout,
 *                      unsigned int ack_delay_count);
 */
static PyObject* pycsp_rdp_set_opt(PyObject *self, PyObject *args) {
    unsigned int window_size;
    unsigned int conn_timeout_ms;
    unsigned int packet_timeout_ms;
    unsigned int delayed_acks;
    unsigned int ack_timeout;
    unsigned int ack_delay_count;
    if (!PyArg_ParseTuple(args, "IIIIII", &window_size, &conn_timeout_ms,
                          &packet_timeout_ms, &delayed_acks,
                          &ack_timeout, &ack_delay_count)) {
        return NULL; // TypeError is thrown
    }
#if (CSP_USE_RDP)
    csp_rdp_set_opt(window_size, conn_timeout_ms, packet_timeout_ms,
                    delayed_acks, ack_timeout, ack_delay_count);
#endif
    Py_RETURN_NONE;
}

/*
 * void csp_rdp_get_opt(unsigned int *window_size,
 *                      unsigned int *conn_timeout_ms,
 *                      unsigned int *packet_timeout_ms,
 *                      unsigned int *delayed_acks,
 *                      unsigned int *ack_timeout,
 *                      unsigned int *ack_delay_count);
 */
static PyObject* pycsp_rdp_get_opt(PyObject *self, PyObject *args) {

    unsigned int window_size = 0;
    unsigned int conn_timeout_ms = 0;
    unsigned int packet_timeout_ms = 0;
    unsigned int delayed_acks = 0;
    unsigned int ack_timeout = 0;
    unsigned int ack_delay_count = 0;
#if (CSP_USE_RDP)
    csp_rdp_get_opt(&window_size,
                    &conn_timeout_ms,
                    &packet_timeout_ms,
                    &delayed_acks,
                    &ack_timeout,
                    &ack_delay_count);
#endif
    return Py_BuildValue("IIIIII",
                         window_size,
                         conn_timeout_ms,
                         packet_timeout_ms,
                         delayed_acks,
                         ack_timeout,
                         ack_delay_count);
}

static PyObject* pycsp_xtea_set_key(PyObject *self, PyObject *args) {
    char* key;
    uint32_t keylen;
    if (!PyArg_ParseTuple(args, "si", &key, &keylen)) {
        return NULL; // TypeError is thrown
    }
    return Py_BuildValue("i", csp_xtea_set_key(key, keylen));
}

static PyObject* pycsp_rtable_set(PyObject *self, PyObject *args) {
    uint8_t node;
    uint8_t mask;
    char* interface_name;
    uint8_t via = CSP_NO_VIA_ADDRESS;
    if (!PyArg_ParseTuple(args, "bbs|b", &node, &mask, &interface_name, &via)) {
        return NULL; // TypeError is thrown
    }

    return Py_BuildValue("i", csp_rtable_set(node,
                                             mask,
                                             csp_iflist_get_by_name(interface_name),
                                             via));
}

static PyObject* pycsp_rtable_clear(PyObject *self, PyObject *args) {
    csp_rtable_clear();
    Py_RETURN_NONE;
}

static PyObject* pycsp_rtable_check(PyObject *self, PyObject *args) {
    char* buffer;
    if (!PyArg_ParseTuple(args, "s", &buffer)) {
        return NULL; // TypeError is thrown
    }

    return Py_BuildValue("i", csp_rtable_check(buffer));
}

static PyObject* pycsp_rtable_load(PyObject *self, PyObject *args) {
    char* buffer;
    if (!PyArg_ParseTuple(args, "s", &buffer)) {
        return NULL; // TypeError is thrown
    }

    csp_rtable_load(buffer);
    Py_RETURN_NONE;
}

static PyObject* pycsp_buffer_get(PyObject *self, PyObject *args) {
    size_t size;
    if (!PyArg_ParseTuple(args, "n", &size)) {
        return NULL; // TypeError is thrown
    }

    void* packet = csp_buffer_get(size);
    if (packet == NULL) {
        Py_RETURN_NONE;
    }

    return PyCapsule_New(packet, "csp_packet_t", pycsp_free_csp_buffer);
}

static PyObject* pycsp_buffer_free(PyObject *self, PyObject *args) {
    PyObject* packet_capsule;
    if (!PyArg_ParseTuple(args, "O", &packet_capsule)) {
        return NULL; // TypeError is thrown
    }

    if (!is_capsule_of_type(packet_capsule, "csp_packet_t")) {
        return NULL; // TypeError is thrown
    }

    csp_buffer_free(PyCapsule_GetPointer(packet_capsule, "csp_packet_t"));
    PyCapsule_SetPointer(packet_capsule, &CSP_POINTER_HAS_BEEN_FREED);
    Py_RETURN_NONE;
}

/*
 * int csp_buffer_remaining(void);
 */
static PyObject* pycsp_buffer_remaining(PyObject *self, PyObject *args) {
    return Py_BuildValue("i", csp_buffer_remaining());
}

/**
 * csp/csp_cmp.h
 */

/*
 * static inline int csp_cmp_ident(uint8_t node, uint32_t timeout,
 *                                 struct csp_cmp_message *msg)
 */
static PyObject* pycsp_cmp_ident(PyObject *self, PyObject *args) {
    uint8_t node;
    uint32_t timeout = 1000;
    if (!PyArg_ParseTuple(args, "b|i", &node, &timeout)) {
        return NULL; // TypeError is thrown
    }

    struct csp_cmp_message msg;
    memset(&msg, 0, sizeof(msg));
    int res;
    Py_BEGIN_ALLOW_THREADS;
    res = csp_cmp_ident(node, timeout, &msg);
    Py_END_ALLOW_THREADS;
    if (res != CSP_ERR_NONE) {
        Py_RETURN_NONE;
    }
    return Py_BuildValue("isssss",
                         res,
                         msg.ident.hostname,
                         msg.ident.model,
                         msg.ident.revision,
                         msg.ident.date,
                         msg.ident.time);
}

/*
 * static inline int csp_cmp_route_set(uint8_t node, uint32_t timeout,
 *                                 struct csp_cmp_message *msg)
 */
static PyObject* pycsp_cmp_route_set(PyObject *self, PyObject *args) {
    uint8_t node;
    uint32_t timeout = 1000;
    uint8_t addr;
    uint8_t via;
    char* ifstr;
    if (!PyArg_ParseTuple(args, "bibbs", &node, &timeout, &addr, &via, &ifstr)) {
        return NULL; // TypeError is thrown
    }

    struct csp_cmp_message msg;
    memset(&msg, 0, sizeof(msg));
    msg.route_set.dest_node = addr;
    msg.route_set.next_hop_via = via;
    strncpy(msg.route_set.interface, ifstr, sizeof(msg.route_set.interface) - 1);

    int res;
    Py_BEGIN_ALLOW_THREADS;
    res = csp_cmp_route_set(node, timeout, &msg);
    Py_END_ALLOW_THREADS;

    return Py_BuildValue("i", res);
}

/* static inline int pycsp_cmp_peek(uint8_t node, uint32_t timeout, struct csp_cmp_message *msg); */
static PyObject* pycsp_cmp_peek(PyObject *self, PyObject *args) {
    uint8_t node;
    uint32_t timeout;
    uint8_t len;
    uint32_t addr;
    Py_buffer outbuf;

    if (!PyArg_ParseTuple(args, "biibw*", &node, &timeout, &addr, &len, &outbuf)) {
        Py_RETURN_NONE;
    }

    if (len > CSP_CMP_PEEK_MAX_LEN) {
        len = CSP_CMP_PEEK_MAX_LEN;
    }
    struct csp_cmp_message msg;
    memset(&msg, 0, sizeof(msg));
    msg.peek.addr = csp_hton32(addr);
    msg.peek.len = len;

    int res;
    Py_BEGIN_ALLOW_THREADS;
    res = csp_cmp_peek(node, timeout, &msg);
    Py_END_ALLOW_THREADS;
    if (res != CSP_ERR_NONE) {
        Py_RETURN_NONE;
    }
    memcpy(outbuf.buf, msg.peek.data, len);
    outbuf.len = len;

    return Py_BuildValue("i", res);
}

/* static inline int pycsp_cmp_poke(uint8_t node, uint32_t timeout, struct csp_cmp_message *msg); */
static PyObject* pycsp_cmp_poke(PyObject *self, PyObject *args) {
    uint8_t node;
    uint32_t timeout;
    uint8_t len;
    uint32_t addr;
    Py_buffer inbuf;

    if (!PyArg_ParseTuple(args, "biibw*", &node, &timeout, &addr, &len, &inbuf)) {
        Py_RETURN_NONE;
    }

    if (len > CSP_CMP_POKE_MAX_LEN) {
        len = CSP_CMP_POKE_MAX_LEN;
    }
    struct csp_cmp_message msg;
    msg.poke.addr = csp_hton32(addr);
    msg.poke.len = len;
    memcpy(msg.poke.data, inbuf.buf, len);

    int res;
    Py_BEGIN_ALLOW_THREADS;
    res = csp_cmp_poke(node, timeout, &msg);
    Py_END_ALLOW_THREADS;
    if (res != CSP_ERR_NONE) {
        Py_RETURN_NONE;
    }

    return Py_BuildValue("i", res);
}

/* static inline int csp_cmp_clock(uint8_t node, uint32_t timeout, struct csp_cmp_message *msg); */
static PyObject* pycsp_cmp_clock(PyObject *self, PyObject *args) {
    uint8_t node;
    uint32_t timeout;
    uint32_t sec;
    uint32_t nsec;
    if (!PyArg_ParseTuple(args, "bIII", &node, &timeout, &sec, &nsec)) {
        Py_RETURN_NONE;
    }

    struct csp_cmp_message msg;
    memset(&msg, 0, sizeof(msg));
    msg.clock.tv_sec = csp_hton32(sec);
    msg.clock.tv_nsec = csp_hton32(nsec);

    int res;
    Py_BEGIN_ALLOW_THREADS;
    res = csp_cmp_clock(node, timeout, &msg);
    Py_END_ALLOW_THREADS;
    return Py_BuildValue("i", res);
}

/**
 * CSP interfaces
 */

static PyObject* pycsp_zmqhub_init(PyObject *self, PyObject *args) {
    char addr;
    char* host;
    if (!PyArg_ParseTuple(args, "bs", &addr, &host)) {
        return NULL; // TypeError is thrown
    }

    int res = csp_zmqhub_init(addr, host, 0, NULL);
    if (res != CSP_ERR_NONE) {
        return PyErr_GenericError("csp_zmqhub_init()", res);
    }

    Py_RETURN_NONE;
}

static PyObject* pycsp_can_socketcan_init(PyObject *self, PyObject *args) {
    char* ifc;
    int bitrate = 1000000;
    int promisc = 0;
    if (!PyArg_ParseTuple(args, "s|ii", &ifc, &bitrate, &promisc)) {
        return NULL;
    }

    int res = csp_can_socketcan_open_and_add_interface(ifc, CSP_IF_CAN_DEFAULT_NAME, bitrate, promisc, NULL);
    csp_log_error("failed, res: %d", res);
    if (res != CSP_ERR_NONE) {
        return PyErr_GenericError("csp_can_socketcan_open_and_add_interface()", res);
    }

    Py_RETURN_NONE;
}

static PyObject* pycsp_kiss_init(PyObject *self, PyObject *args) {
    char* device;
    uint32_t baudrate = 500000;
    uint32_t mtu = 512;
    const char* if_name = CSP_IF_KISS_DEFAULT_NAME;
    if (!PyArg_ParseTuple(args, "s|IIs", &device, &baudrate, &mtu, &if_name)) {
        return NULL; // TypeError is thrown
    }

    csp_usart_conf_t conf = {.device = device, .baudrate = baudrate};
    int res = csp_usart_open_and_add_kiss_interface(&conf, if_name, NULL);
    if (res != CSP_ERR_NONE) {
        return PyErr_GenericError("csp_usart_open_and_add_kiss_interface()", res);
    }

    Py_RETURN_NONE;
}

/**
 * Helpers - accessing csp_packet_t members
 */
static PyObject* pycsp_packet_set_data(PyObject *self, PyObject *args) {
    PyObject* packet_capsule;
    Py_buffer data;
    if (!PyArg_ParseTuple(args, "Ow*", &packet_capsule, &data)) {
        return NULL; // TypeError is thrown
    }

    if (!is_capsule_of_type(packet_capsule, "csp_packet_t")) {
        return NULL; // TypeError is thrown
    }

    csp_packet_t* packet = PyCapsule_GetPointer(packet_capsule, "csp_packet_t");

    memcpy(packet->data, data.buf, data.len);
    packet->length = data.len;

    Py_RETURN_NONE;
}
static PyObject* pycsp_packet_get_data(PyObject *self, PyObject *packet_capsule) {
    if (!is_capsule_of_type(packet_capsule, "csp_packet_t")) {
        return NULL; // TypeError is thrown
    }

    csp_packet_t* packet = PyCapsule_GetPointer(packet_capsule, "csp_packet_t");
#if (PY_MAJOR_VERSION >= 3)
    return Py_BuildValue("y#", packet->data, packet->length);
#else
    return Py_BuildValue("s#", packet->data, packet->length);
#endif
}

static PyObject* pycsp_packet_get_length(PyObject *self, PyObject *packet_capsule) {
    if (!is_capsule_of_type(packet_capsule, "csp_packet_t")) {
        return NULL; // TypeError is thrown
    }

    csp_packet_t* packet = PyCapsule_GetPointer(packet_capsule, "csp_packet_t");
    return Py_BuildValue("H", packet->length);
}

static PyObject* pycsp_print_connections(PyObject *self, PyObject *args) {
#if (CSP_DEBUG)
    csp_conn_print_table();
#endif
    Py_RETURN_NONE;
}

static PyObject* pycsp_print_routes(PyObject *self, PyObject *args) {
#if (CSP_DEBUG)
    csp_rtable_print();
#endif
    Py_RETURN_NONE;
}

static PyObject* pycsp_get_buffer_stats(PyObject *self, PyObject *args) {
    return Py_BuildValue("iii", (int)csp_buffer_remaining(), (int)csp_buffer_size(), (int)csp_buffer_data_size());
}

static PyMethodDef methods[] = {

    /* csp/csp.h */
    {"service_handler", pycsp_service_handler, METH_VARARGS, ""},
    {"init", pycsp_init, METH_VARARGS, ""},
    {"get_hostname", pycsp_get_hostname, METH_NOARGS, ""},
    {"get_model", pycsp_get_model, METH_NOARGS, ""},
    {"get_revision", pycsp_get_revision, METH_NOARGS, ""},
    {"socket", pycsp_socket, METH_VARARGS, ""},
    {"accept", pycsp_accept, METH_VARARGS, ""},
    {"read", pycsp_read, METH_VARARGS, ""},
    {"send", pycsp_send, METH_VARARGS, ""},
    {"transaction", pycsp_transaction, METH_VARARGS, ""},
    {"sendto_reply", pycsp_sendto_reply, METH_VARARGS, ""},
    {"sendto", pycsp_sendto, METH_VARARGS, ""},
    {"connect", pycsp_connect, METH_VARARGS, ""},
    {"close", pycsp_close, METH_O, ""},
    {"conn_dport", pycsp_conn_dport, METH_O, ""},
    {"conn_sport", pycsp_conn_sport, METH_O, ""},
    {"conn_dst", pycsp_conn_dst, METH_O, ""},
    {"conn_src", pycsp_conn_src, METH_O, ""},
    {"listen", pycsp_listen, METH_VARARGS, ""},
    {"bind", pycsp_bind, METH_VARARGS, ""},
    {"route_start_task", pycsp_route_start_task, METH_VARARGS, ""},
    {"ping", pycsp_ping, METH_VARARGS, ""},
    {"reboot", pycsp_reboot, METH_VARARGS, ""},
    {"shutdown", pycsp_shutdown, METH_VARARGS, ""},
    {"rdp_set_opt", pycsp_rdp_set_opt, METH_VARARGS, ""},
    {"rdp_get_opt", pycsp_rdp_get_opt, METH_NOARGS, ""},
    {"xtea_set_key", pycsp_xtea_set_key, METH_VARARGS, ""},

    /* csp/csp_rtable.h */
    {"rtable_set", pycsp_rtable_set, METH_VARARGS, ""},
    {"rtable_clear", pycsp_rtable_clear, METH_NOARGS, ""},
    {"rtable_check", pycsp_rtable_check, METH_VARARGS, ""},
    {"rtable_load", pycsp_rtable_load, METH_VARARGS, ""},

    /* csp/csp_buffer.h */
    {"buffer_free", pycsp_buffer_free, METH_VARARGS, ""},
    {"buffer_get", pycsp_buffer_get, METH_VARARGS, ""},
    {"buffer_remaining", pycsp_buffer_remaining, METH_NOARGS, ""},

    /* csp/csp_cmp.h */
    {"cmp_ident", pycsp_cmp_ident, METH_VARARGS, ""},
    {"cmp_route_set", pycsp_cmp_route_set, METH_VARARGS, ""},
    {"cmp_peek", pycsp_cmp_peek, METH_VARARGS, ""},
    {"cmp_poke", pycsp_cmp_poke, METH_VARARGS, ""},
    {"cmp_clock", pycsp_cmp_clock, METH_VARARGS, ""},


    /* csp/interfaces/csp_if_zmqhub.h */
    {"zmqhub_init", pycsp_zmqhub_init, METH_VARARGS, ""},
    {"kiss_init", pycsp_kiss_init, METH_VARARGS, ""},

    /* csp/drivers/can_socketcan.h */
    {"can_socketcan_init", pycsp_can_socketcan_init, METH_VARARGS, ""},

    /* helpers */
    {"packet_get_length", pycsp_packet_get_length, METH_O, ""},
    {"packet_get_data", pycsp_packet_get_data, METH_O, ""},
    {"packet_set_data", pycsp_packet_set_data, METH_VARARGS, ""},
    {"print_connections", pycsp_print_connections, METH_NOARGS, ""},
    {"print_routes", pycsp_print_routes, METH_NOARGS, ""},
    {"get_buffer_stats", pycsp_get_buffer_stats, METH_NOARGS, ""},

    /* sentinel */
    {NULL, NULL, 0, NULL}
};

#if (PY_MAJOR_VERSION >= 3)
static struct PyModuleDef moduledef = {
    PyModuleDef_HEAD_INIT,
    "libcsp_py3",
    NULL,
    -1,
    methods,
    NULL,
    NULL,
    NULL,
    NULL
};
#endif

#if (PY_MAJOR_VERSION >= 3)
PyMODINIT_FUNC PyInit_libcsp_py3(void) {
#else
    PyMODINIT_FUNC initlibcsp_py2(void) {
#endif

        PyObject* m;

#if (PY_MAJOR_VERSION >= 3)
        m = PyModule_Create(&moduledef);
#else
        m = Py_InitModule("libcsp_py2", methods);
#endif

        /* Exceptions */
        GenericError = PyErr_NewException((char*)"csp.GenericError", NULL, NULL);

        /* Add exception object to your module */
        PyModule_AddObject(m, "GenericError", GenericError);

        /* RESERVED PORTS */
        PyModule_AddIntConstant(m, "CSP_CMP", CSP_CMP);
        PyModule_AddIntConstant(m, "CSP_PING", CSP_PING);
        PyModule_AddIntConstant(m, "CSP_PS", CSP_PS);
        PyModule_AddIntConstant(m, "CSP_MEMFREE", CSP_MEMFREE);
        PyModule_AddIntConstant(m, "CSP_REBOOT", CSP_REBOOT);
        PyModule_AddIntConstant(m, "CSP_BUF_FREE", CSP_BUF_FREE);
        PyModule_AddIntConstant(m, "CSP_UPTIME", CSP_UPTIME);
        PyModule_AddIntConstant(m, "CSP_ANY", CSP_ANY);

        /* PRIORITIES */
        PyModule_AddIntConstant(m, "CSP_PRIO_CRITICAL", CSP_PRIO_CRITICAL);
        PyModule_AddIntConstant(m, "CSP_PRIO_HIGH", CSP_PRIO_HIGH);
        PyModule_AddIntConstant(m, "CSP_PRIO_NORM", CSP_PRIO_NORM);
        PyModule_AddIntConstant(m, "CSP_PRIO_LOW", CSP_PRIO_LOW);

        /* FLAGS */
        PyModule_AddIntConstant(m, "CSP_FFRAG", CSP_FFRAG);
        PyModule_AddIntConstant(m, "CSP_FHMAC", CSP_FHMAC);
        PyModule_AddIntConstant(m, "CSP_FXTEA", CSP_FXTEA);
        PyModule_AddIntConstant(m, "CSP_FRDP", CSP_FRDP);
        PyModule_AddIntConstant(m, "CSP_FCRC32", CSP_FCRC32);

        /* SOCKET OPTIONS */
        PyModule_AddIntConstant(m, "CSP_SO_NONE", CSP_SO_NONE);
        PyModule_AddIntConstant(m, "CSP_SO_RDPREQ", CSP_SO_RDPREQ);
        PyModule_AddIntConstant(m, "CSP_SO_RDPPROHIB", CSP_SO_RDPPROHIB);
        PyModule_AddIntConstant(m, "CSP_SO_HMACREQ", CSP_SO_HMACREQ);
        PyModule_AddIntConstant(m, "CSP_SO_HMACPROHIB", CSP_SO_HMACPROHIB);
        PyModule_AddIntConstant(m, "CSP_SO_XTEAREQ", CSP_SO_XTEAREQ);
        PyModule_AddIntConstant(m, "CSP_SO_XTEAPROHIB", CSP_SO_XTEAPROHIB);
        PyModule_AddIntConstant(m, "CSP_SO_CRC32REQ", CSP_SO_CRC32REQ);
        PyModule_AddIntConstant(m, "CSP_SO_CRC32PROHIB", CSP_SO_CRC32PROHIB);
        PyModule_AddIntConstant(m, "CSP_SO_CONN_LESS", CSP_SO_CONN_LESS);

        /* CONNECT OPTIONS */
        PyModule_AddIntConstant(m, "CSP_O_NONE", CSP_O_NONE);
        PyModule_AddIntConstant(m, "CSP_O_RDP", CSP_O_RDP);
        PyModule_AddIntConstant(m, "CSP_O_NORDP", CSP_O_NORDP);
        PyModule_AddIntConstant(m, "CSP_O_HMAC", CSP_O_HMAC);
        PyModule_AddIntConstant(m, "CSP_O_NOHMAC", CSP_O_NOHMAC);
        PyModule_AddIntConstant(m, "CSP_O_XTEA", CSP_O_XTEA);
        PyModule_AddIntConstant(m, "CSP_O_NOXTEA", CSP_O_NOXTEA);
        PyModule_AddIntConstant(m, "CSP_O_CRC32", CSP_O_CRC32);
        PyModule_AddIntConstant(m, "CSP_O_NOCRC32", CSP_O_NOCRC32);

        /* csp/csp_error.h */
        PyModule_AddIntConstant(m, "CSP_ERR_NONE", CSP_ERR_NONE);
        PyModule_AddIntConstant(m, "CSP_ERR_NOMEM", CSP_ERR_NOMEM);
        PyModule_AddIntConstant(m, "CSP_ERR_INVAL", CSP_ERR_INVAL);
        PyModule_AddIntConstant(m, "CSP_ERR_TIMEDOUT", CSP_ERR_TIMEDOUT);
        PyModule_AddIntConstant(m, "CSP_ERR_USED", CSP_ERR_USED);
        PyModule_AddIntConstant(m, "CSP_ERR_NOTSUP", CSP_ERR_NOTSUP);
        PyModule_AddIntConstant(m, "CSP_ERR_BUSY", CSP_ERR_BUSY);
        PyModule_AddIntConstant(m, "CSP_ERR_ALREADY", CSP_ERR_ALREADY);
        PyModule_AddIntConstant(m, "CSP_ERR_RESET", CSP_ERR_RESET);
        PyModule_AddIntConstant(m, "CSP_ERR_NOBUFS", CSP_ERR_NOBUFS);
        PyModule_AddIntConstant(m, "CSP_ERR_TX", CSP_ERR_TX);
        PyModule_AddIntConstant(m, "CSP_ERR_DRIVER", CSP_ERR_DRIVER);
        PyModule_AddIntConstant(m, "CSP_ERR_AGAIN", CSP_ERR_AGAIN);
        PyModule_AddIntConstant(m, "CSP_ERR_HMAC", CSP_ERR_HMAC);
        PyModule_AddIntConstant(m, "CSP_ERR_XTEA", CSP_ERR_XTEA);
        PyModule_AddIntConstant(m, "CSP_ERR_CRC32", CSP_ERR_CRC32);
        PyModule_AddIntConstant(m, "CSP_ERR_SFP", CSP_ERR_SFP);

        /* misc */
        PyModule_AddIntConstant(m, "CSP_NODE_MAC", CSP_NODE_MAC);
        PyModule_AddIntConstant(m, "CSP_NO_VIA_ADDRESS", CSP_NO_VIA_ADDRESS);
        PyModule_AddIntConstant(m, "CSP_MAX_TIMEOUT", CSP_MAX_TIMEOUT);

#if (PY_MAJOR_VERSION >= 3)
        return m;
#endif
    }

