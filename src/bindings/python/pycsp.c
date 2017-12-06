#include <Python.h>
#include <csp/csp_endian.h>
#include <csp/csp.h>
#include <csp/csp_error.h>
#include <csp/csp_rtable.h>
#include <csp/csp_buffer.h>
#include <csp/csp_cmp.h>
#include <csp/interfaces/csp_if_zmqhub.h>
#include <csp/interfaces/csp_if_can.h>

#if PY_MAJOR_VERSION == 3
#define IS_PY3
#endif

/**
 * csp/csp.h
 */

/* int csp_init(uint8_t my_node_address); */
static PyObject* pycsp_init(PyObject *self, PyObject *args) {
    uint8_t my_node_address;
    if (!PyArg_ParseTuple(args, "b", &my_node_address)) {
        Py_RETURN_NONE;
    }

    return Py_BuildValue("i", csp_init(my_node_address));
}

/* void csp_set_address(uint8_t addr); */
static PyObject* pycsp_set_address(PyObject *self, PyObject *args) {
    uint8_t addr;
    if (!PyArg_ParseTuple(args, "b", &addr)) {
        Py_RETURN_NONE;
    }

    csp_set_address(addr);
    Py_RETURN_NONE;
}

/* uint8_t csp_get_address(void); */
static PyObject* pycsp_get_address(PyObject *self, PyObject *args) {
    return Py_BuildValue("b", csp_get_address());
}

/* void csp_set_hostname(const char *hostname); */
static PyObject* pycsp_set_hostname(PyObject *self, PyObject *args) {
    char* hostname;
    if (!PyArg_ParseTuple(args, "s", &hostname)) {
        Py_RETURN_NONE;
    }

    csp_set_hostname(hostname);
    Py_RETURN_NONE;
}

/* const char *csp_get_hostname(void); */
static PyObject* pycsp_get_hostname(PyObject *self, PyObject *args) {
    return Py_BuildValue("s", csp_get_hostname());
}

/* void csp_set_model(const char *model); */
static PyObject* pycsp_set_model(PyObject *self, PyObject *args) {
    char* model;
    if (!PyArg_ParseTuple(args, "s", &model)) {
        Py_RETURN_NONE;
    }

    csp_set_model(model);
    Py_RETURN_NONE;
}

/* const char *csp_get_model(void); */
static PyObject* pycsp_get_model(PyObject *self, PyObject *args) {
    return Py_BuildValue("s", csp_get_model());
}

/* void csp_set_revision(const char *revision); */
static PyObject* pycsp_set_revision(PyObject *self, PyObject *args) {
    char* revision;
    if (!PyArg_ParseTuple(args, "s", &revision)) {
        Py_RETURN_NONE;
    }

    csp_set_revision(revision);
    Py_RETURN_NONE;
}

/* const char *csp_get_revision(void); */
static PyObject* pycsp_get_revision(PyObject *self, PyObject *args) {
    return Py_BuildValue("s", csp_get_revision());
}

/* csp_socket_t *csp_socket(uint32_t opts); */
static PyObject* pycsp_socket(PyObject *self, PyObject *args) {
    uint32_t opts = CSP_SO_NONE;
    if (!PyArg_ParseTuple(args, "|I", &opts)) {
        Py_RETURN_NONE;
    }

    return PyCapsule_New(csp_socket(opts), "csp_socket_t", NULL);
}

/* csp_conn_t *csp_accept(csp_socket_t *socket, uint32_t timeout); */
static PyObject* pycsp_accept(PyObject *self, PyObject *args) {
    PyObject* socket_capsule;
    uint32_t timeout;
    if (!PyArg_ParseTuple(args, "OI", &socket_capsule, &timeout)) {
        Py_RETURN_NONE;
    }

    void* socket = PyCapsule_GetPointer(socket_capsule, "csp_socket_t");
    if (socket == NULL) {
        Py_RETURN_NONE;
    }

    csp_conn_t* conn = csp_accept((csp_socket_t*)socket, timeout);
    if (conn == NULL) {
        Py_RETURN_NONE;
    }
    return PyCapsule_New(conn, "csp_conn_t", NULL);
}

/* csp_packet_t *csp_read(csp_conn_t *conn, uint32_t timeout); */
static PyObject* pycsp_read(PyObject *self, PyObject *args) {
    PyObject* conn_capsule;
    uint32_t timeout;
    if (!PyArg_ParseTuple(args, "OI", &conn_capsule, &timeout)) {
        Py_RETURN_NONE;
    }

    void* conn = PyCapsule_GetPointer(conn_capsule, "csp_conn_t");
    if (conn == NULL) {
        Py_RETURN_NONE;
    }

    csp_packet_t* packet = csp_read((csp_conn_t*)conn, timeout);
    if (packet == NULL) {
        Py_RETURN_NONE;
    }

    return PyCapsule_New(packet, "csp_packet_t", NULL);
}

/* int csp_send(csp_conn_t *conn, csp_packet_t *packet, uint32_t timeout); */
static PyObject* pycsp_send(PyObject *self, PyObject *args) {
    PyObject* conn_capsule;
    PyObject* packet_capsule;
    uint32_t timeout;
    if (!PyArg_ParseTuple(args, "OOI", &conn_capsule, &packet_capsule, &timeout)) {
        Py_RETURN_NONE;
    }

    void* conn = PyCapsule_GetPointer(conn_capsule, "csp_conn_t");
    if (conn == NULL) {
        Py_RETURN_NONE;
    }

    // TODO: will this leak if conn == NULL
    void* packet = PyCapsule_GetPointer(packet_capsule, "csp_packet_t");
    if (packet == NULL) {
        Py_RETURN_NONE;
    }

    return Py_BuildValue("i", csp_send((csp_conn_t*)conn,
                                       (csp_packet_t*)packet,
                                       timeout));
}

/* int csp_transaction(uint8_t prio, uint8_t dest, uint8_t port, uint32_t timeout, void *outbuf, int outlen, void *inbuf, int inlen); */
static PyObject* pycsp_transaction(PyObject *self, PyObject *args) {
    uint8_t prio;
    uint8_t dest;
    uint8_t port;
    uint32_t timeout;
    Py_buffer inbuf;
    Py_buffer outbuf;
    if (!PyArg_ParseTuple(args, "bbbIw*w*", &prio, &dest, &port, &timeout, &outbuf, &inbuf)) {
        Py_RETURN_NONE;
    }

    int result = csp_transaction(prio,
                                 dest,
                                 port,
                                 timeout,
                                 outbuf.buf,
                                 outbuf.len,
                                 inbuf.buf,
                                 inbuf.len);

    return Py_BuildValue("i", result);
}

/* csp_packet_t *csp_recvfrom(csp_socket_t *socket, uint32_t timeout); */
static PyObject* pycsp_recvfrom(PyObject *self, PyObject *args) {
    PyObject* socket_capsule;
    uint32_t timeout;
    if (!PyArg_ParseTuple(args, "OI", &socket_capsule, &timeout)) {
        Py_RETURN_NONE;
    }

    void* socket = PyCapsule_GetPointer(socket_capsule, "csp_socket_t");
    if (socket == NULL)  {
        Py_RETURN_NONE;
    }

    csp_packet_t* packet = csp_recvfrom(socket, timeout);
    if (packet == NULL) {
        Py_RETURN_NONE;
    }

    return PyCapsule_New(packet, "csp_packet_t", NULL);
}

/* int csp_sendto(uint8_t prio, uint8_t dest, uint8_t dport, uint8_t src_port, uint32_t opts, csp_packet_t *packet, uint32_t timeout); */
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

    void* packet = PyCapsule_GetPointer(packet_capsule, "csp_packet_t");
    if (packet == NULL) {
        Py_RETURN_NONE;
    }

    return Py_BuildValue("i", csp_sendto(prio,
                                         dest,
                                         dport,
                                         src_port,
                                         opts,
                                         (csp_packet_t*)packet,
                                         timeout));
}

/* int csp_sendto_reply(csp_packet_t * request_packet, csp_packet_t * reply_packet, uint32_t opts, uint32_t timeout); */
static PyObject* pycsp_sendto_reply(PyObject *self, PyObject *args) {
    PyObject* request_packet_capsule;
    PyObject* reply_packet_capsule;
    uint32_t opts;
    uint32_t timeout;
    if (!PyArg_ParseTuple(args, "OOII", &request_packet_capsule, &reply_packet_capsule, &opts, &timeout)) {
        Py_RETURN_NONE;
    }

    void* request_packet = PyCapsule_GetPointer(request_packet_capsule, "csp_packet_t");
    void* reply_packet = PyCapsule_GetPointer(reply_packet_capsule, "csp_packet_t");

    // TODO: leaks if either is zero?
    if (request_packet == NULL || reply_packet == NULL) {
        Py_RETURN_NONE;
    }

    return Py_BuildValue("i", csp_sendto_reply((csp_packet_t*)request_packet,
                                               (csp_packet_t*)reply_packet,
                                               opts,
                                               timeout));
}

/* csp_conn_t *csp_connect(uint8_t prio, uint8_t dest, uint8_t dport, uint32_t timeout, uint32_t opts); */
static PyObject* pycsp_connect(PyObject *self, PyObject *args) {
    uint8_t prio;
    uint8_t dest;
    uint8_t dport;
    uint32_t timeout;
    uint32_t opts;
    if (!PyArg_ParseTuple(args, "bbbII", &prio, &dest, &dport, &timeout, &opts)) {
        Py_RETURN_NONE;
    }

    csp_conn_t* conn = csp_connect(prio, dest, dport, timeout, opts);
    if (conn == NULL) {
        Py_RETURN_NONE;
    }

    return PyCapsule_New(conn, "csp_conn_t", NULL);
}

/* int csp_close(csp_conn_t *conn); */
static PyObject* pycsp_close(PyObject *self, PyObject *args) {
    PyObject* conn_capsule;
    if (!PyArg_ParseTuple(args, "O", &conn_capsule)) {
        Py_RETURN_NONE;
    }
    void *conn = PyCapsule_GetPointer(conn_capsule, "csp_conn_t");
    if (conn == NULL) {
        Py_RETURN_NONE;
    }

    return Py_BuildValue("i", csp_close((csp_conn_t*)conn));
}

/* int csp_conn_dport(csp_conn_t *conn); */
static PyObject* pycsp_conn_dport(PyObject *self, PyObject *args) {
    PyObject* conn_capsule;
    if (!PyArg_ParseTuple(args, "O", &conn_capsule)) {
        Py_RETURN_NONE;
    }

    void* conn = PyCapsule_GetPointer(conn_capsule, "csp_conn_t");
    if (conn == NULL) {
        Py_RETURN_NONE;
    }

    return Py_BuildValue("i", csp_conn_dport((csp_conn_t*)conn));
}

/* int csp_conn_sport(csp_conn_t *conn); */
static PyObject* pycsp_conn_sport(PyObject *self, PyObject *args) {
    PyObject* conn_capsule;
    if (!PyArg_ParseTuple(args, "O", &conn_capsule)) {
        Py_RETURN_NONE;
    }

    void* conn = PyCapsule_GetPointer(conn_capsule, "csp_conn_t");
    if (conn == NULL) {
        Py_RETURN_NONE;
    }

    return Py_BuildValue("i", csp_conn_sport((csp_conn_t*)conn));
}

/* int csp_conn_dst(csp_conn_t *conn); */
static PyObject* pycsp_conn_dst(PyObject *self, PyObject *args) {
    PyObject* conn_capsule;
    if (!PyArg_ParseTuple(args, "O", &conn_capsule)) {
        Py_RETURN_NONE;
    }

    void* conn = PyCapsule_GetPointer(conn_capsule, "csp_conn_t");
    if (conn == NULL) {
        Py_RETURN_NONE;
    }

    return Py_BuildValue("i", csp_conn_dst((csp_conn_t*)conn));
}

/* int csp_conn_src(csp_conn_t *conn); */
static PyObject* pycsp_conn_src(PyObject *self, PyObject *args) {
    PyObject* conn_capsule;
    if (!PyArg_ParseTuple(args, "O", &conn_capsule)) {
        Py_RETURN_NONE;
    }

    void* conn = PyCapsule_GetPointer(conn_capsule, "csp_conn_t");
    if (conn == NULL) {
        Py_RETURN_NONE;
    }

    return Py_BuildValue("i", csp_conn_src((csp_conn_t*)conn));
}

/* int csp_listen(csp_socket_t *socket, size_t conn_queue_length); */
static PyObject* pycsp_listen(PyObject *self, PyObject *args) {
    PyObject* socket_capsule;
    size_t conn_queue_len;
    if (!PyArg_ParseTuple(args, "On", &socket_capsule, &conn_queue_len)) {
        Py_RETURN_NONE;
    }

    void* sock = PyCapsule_GetPointer(socket_capsule, "csp_socket_t");
    if (sock == NULL) {
        Py_RETURN_NONE;
    }

    return Py_BuildValue("i", csp_listen((csp_socket_t*)sock, conn_queue_len));
}

/* int csp_bind(csp_socket_t *socket, uint8_t port); */
static PyObject* pycsp_bind(PyObject *self, PyObject *args) {
    PyObject* socket_capsule;
    uint8_t port;
    if (!PyArg_ParseTuple(args, "Ob", &socket_capsule, &port)) {
        Py_RETURN_NONE;
    }

    void* sock = PyCapsule_GetPointer(socket_capsule, "csp_socket_t");
    if (sock == NULL) {
        Py_RETURN_NONE;
    }

    return Py_BuildValue("i", csp_bind((csp_socket_t*)sock, port));
}

/* int csp_route_start_task(unsigned int task_stack_size, unsigned int priority); */
static PyObject* pycsp_route_start_task(PyObject *self, PyObject *args) {
    unsigned int task_stack_size;
    unsigned int priority;
    if (!PyArg_ParseTuple(args, "II", &task_stack_size, &priority)) {
        Py_RETURN_NONE;
    }

    return Py_BuildValue("i", csp_route_start_task(task_stack_size, priority));
}

/* int csp_route_work(uint32_t timeout); */
static PyObject* pycsp_route_work(PyObject *self, PyObject *args) {
    unsigned int timeout;
    if (!PyArg_ParseTuple(args, "I", &timeout)) {
        Py_RETURN_NONE;
    }

    return Py_BuildValue("i", csp_route_work(timeout));
}

/* int csp_ping(uint8_t node, uint32_t timeout, unsigned int size, uint8_t conn_options); */
static PyObject* pycsp_ping(PyObject *self, PyObject *args) {
    uint8_t node;
    uint32_t timeout = 1000;
    unsigned int size = 100;
    uint8_t conn_options = CSP_O_NONE;
    if (!PyArg_ParseTuple(args, "b|IIb", &node, &timeout, &size, &conn_options)) {
        Py_RETURN_NONE;
    }

    return Py_BuildValue("i", csp_ping(node, timeout, size, conn_options));
}

/* void csp_ping_noreply(uint8_t node); */
static PyObject* pycsp_ping_noreply(PyObject *self, PyObject *args) {
    uint8_t node;
    if (!PyArg_ParseTuple(args, "b", &node)) {
        Py_RETURN_NONE;
    }

    csp_ping_noreply(node);
    Py_RETURN_NONE;
}

/* void csp_reboot(uint8_t node); */
static PyObject* pycsp_reboot(PyObject *self, PyObject *args) {
    uint8_t node;
    if (!PyArg_ParseTuple(args, "b", &node)) {
        Py_RETURN_NONE;
    }

    csp_reboot(node);
    Py_RETURN_NONE;
}

/* void csp_shutdown(uint8_t node); */
static PyObject* pycsp_shutdown(PyObject *self, PyObject *args) {
    uint8_t node;
    if (!PyArg_ParseTuple(args, "b", &node)) {
        Py_RETURN_NONE;
    }

    csp_shutdown(node);
    Py_RETURN_NONE;
}

/* void csp_rdp_set_opt(unsigned int window_size, unsigned int conn_timeout_ms,
   unsigned int packet_timeout_ms, unsigned int delayed_acks,
   unsigned int ack_timeout, unsigned int ack_delay_count); */
static PyObject* pycsp_rdp_set_opt(PyObject *self, PyObject *args) {
    unsigned int window_size;
    unsigned int conn_timeout_ms;
    unsigned int packet_timeout_ms;
    unsigned int delayed_acks;
    unsigned int ack_timeout;
    unsigned int ack_delay_count;
    if (!PyArg_ParseTuple(args, "IIIIII", &window_size, &conn_timeout_ms, &packet_timeout_ms, &delayed_acks, &ack_timeout, &ack_delay_count)) {
        Py_RETURN_NONE;
    }

    csp_rdp_set_opt(window_size, conn_timeout_ms, packet_timeout_ms, delayed_acks, ack_timeout, ack_delay_count);
    Py_RETURN_NONE;
}

/* void csp_rdp_get_opt(unsigned int *window_size, unsigned int *conn_timeout_ms,
   unsigned int *packet_timeout_ms, unsigned int *delayed_acks,
   unsigned int *ack_timeout, unsigned int *ack_delay_count); */
static PyObject* pycsp_rdp_get_opt(PyObject *self, PyObject *args) {
    unsigned int window_size = 0;
    unsigned int conn_timeout_ms = 0;
    unsigned int packet_timeout_ms = 0;
    unsigned int delayed_acks = 0;
    unsigned int ack_timeout = 0;
    unsigned int ack_delay_count = 0;
    if (!PyArg_ParseTuple(args, "")) {
        Py_RETURN_NONE;
    }

    csp_rdp_get_opt(&window_size,
                    &conn_timeout_ms,
                    &packet_timeout_ms,
                    &delayed_acks,
                    &ack_timeout,
                    &ack_delay_count);

    return Py_BuildValue("IIIIII",
                         window_size,
                         conn_timeout_ms,
                         packet_timeout_ms,
                         delayed_acks,
                         ack_timeout,
                         ack_delay_count);
}

/* void csp_conn_print_table(void); */
static PyObject* pycsp_conn_print_table(PyObject *self, PyObject *args) {
    csp_conn_print_table();
    Py_RETURN_NONE;
}

static PyObject* pycsp_cmp_ident(PyObject *self, PyObject *args) {
    uint8_t node;
    uint32_t timeout;
    if (!PyArg_ParseTuple(args, "bi", &node, &timeout)) {
        Py_RETURN_NONE;
    }

    struct csp_cmp_message msg;
    int rc = csp_cmp_ident(node, timeout, &msg);
    if (rc != CSP_ERR_NONE) {
        Py_RETURN_NONE;
    }

    return Py_BuildValue("sssss",
                         msg.ident.hostname,
                         msg.ident.model,
                         msg.ident.revision,
                         msg.ident.date,
                         msg.ident.time);
}

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
    msg.peek.addr = csp_hton32(addr);
    msg.peek.len = len;
    int rc = csp_cmp_peek(node, timeout, &msg);
    if (rc != CSP_ERR_NONE) {
        Py_RETURN_NONE;
    }
    memcpy(outbuf.buf, msg.peek.data, len);
    outbuf.len = len;

    return Py_BuildValue("i", rc);
}

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
    int rc = csp_cmp_poke(node, timeout, &msg);
    if (rc != CSP_ERR_NONE) {
        Py_RETURN_NONE;
    }

    return Py_BuildValue("i", rc);
}

/**
 * csp/csp_rtable.h
 */

/* int csp_rtable_set(uint8_t node, uint8_t mask, csp_iface_t *ifc, uint8_t mac);*/
static PyObject* pycsp_rtable_set(PyObject *self, PyObject *args) {
    uint8_t node;
    uint8_t mask;
    PyObject* ifc_capsule;
    uint8_t mac;
    if (!PyArg_ParseTuple(args, "bbOb", &node, &mask, &ifc_capsule, &mac)) {
        Py_RETURN_NONE;
    }

    void* iface = PyCapsule_GetPointer(ifc_capsule, "csp_iface_t");
    if (iface == NULL) {
        Py_RETURN_NONE;
    }

    return Py_BuildValue("i", csp_rtable_set(node,
                                             mask,
                                             (csp_iface_t*)iface,
                                             mac));
}

/* void csp_rtable_print(void); */
static PyObject* pycsp_rtable_print(PyObject *self, PyObject *args) {
    csp_rtable_print();
    Py_RETURN_NONE;
}

/* void csp_rtable_clear(void); */
static PyObject* pycsp_rtable_clear(PyObject *self, PyObject *args) {
    csp_rtable_clear();
    Py_RETURN_NONE;
}

/**
 * csp/csp_buffer.h
 */

/* int csp_buffer_init(int count, int size); */
static PyObject* pycsp_buffer_init(PyObject *self, PyObject *args) {
    int count;
    int size;
    if (!PyArg_ParseTuple(args, "ii", &count, &size)) {
        Py_RETURN_NONE;
    }

    return Py_BuildValue("i", csp_buffer_init(count, size));
}

/* void csp_buffer_free(void *packet); */
static PyObject* pycsp_buffer_free(PyObject *self, PyObject *args) {
    PyObject* packet_capsule;
    if (!PyArg_ParseTuple(args, "O", &packet_capsule)) {
        Py_RETURN_NONE;
    }

    void* buffer = PyCapsule_GetPointer(packet_capsule, "void");
    if (buffer == NULL) {
        buffer = PyCapsule_GetPointer(packet_capsule, "csp_packet_t");
        if (buffer == NULL) {
            Py_RETURN_NONE;
        }
    }

    csp_buffer_free(buffer);
    Py_RETURN_NONE;
}

/* int csp_buffer_remaining(void); */
static PyObject* pycsp_buffer_remaining(PyObject *self, PyObject *args) {
    return Py_BuildValue("i", csp_buffer_remaining());
}

/* int csp_buffer_size(void); */
static PyObject* pycsp_buffer_size(PyObject *self, PyObject *args) {
    return Py_BuildValue("i", csp_buffer_size());
}

/**
 * csp/csp_cmp.h
 */

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
    msg.clock.tv_sec = csp_hton32(sec);
    msg.clock.tv_nsec = csp_hton32(nsec);
    return Py_BuildValue("i", csp_cmp_clock(node, timeout, &msg));
}

/**
 * csp/interfaces/csp_if_zmqhub.h
 */

/* int csp_zmqhub_init(char addr, char * host); */
static PyObject* pycsp_zmqhub_init(PyObject *self, PyObject *args) {
    char addr;
    char* host;
    if (!PyArg_ParseTuple(args, "bs", &addr, &host)) {
        Py_RETURN_NONE;
    }

    return Py_BuildValue("i", csp_zmqhub_init(addr, host));
}

/**
 * csp/interfaces/csp_if_can.h
 */

/* int csp_can_init(uint8_t mode, struct csp_can_config *conf); */
static PyObject* pycsp_can_init(PyObject *self, PyObject *args) {
    uint8_t mode;
    const char* ifc = "can0";
    struct csp_can_config conf = {.ifc = (char*)ifc};
    if (!PyArg_ParseTuple(args, "b", &mode)) {
        Py_RETURN_NONE;
    }

    return Py_BuildValue("i", csp_can_init(mode, &conf));
}

/**
 * Helpers - accessing csp_packet_t members
 */
static PyObject* pycsp_packet_data(PyObject *self, PyObject *packet_capsule) {
    csp_packet_t* packet = PyCapsule_GetPointer(packet_capsule, "csp_packet_t");
#ifdef IS_PY3
    return Py_BuildValue("y#", packet->data, packet->length);
#else
    return Py_BuildValue("s#", packet->data, packet->length);
#endif
}

static PyObject* pycsp_packet_length(PyObject *self, PyObject *packet_capsule) {
    csp_packet_t* packet = PyCapsule_GetPointer(packet_capsule, "csp_packet_t");
    return Py_BuildValue("H", packet->length);
}

/**
 * Helpers - return csp_iface_t's as capsules
 */
static PyObject* pycsp_zmqhub_if(PyObject *self, PyObject *args) {
    return PyCapsule_New(&csp_if_zmqhub, "csp_iface_t", NULL);
}

static PyObject* pycsp_can_if(PyObject *self, PyObject *args) {
    return PyCapsule_New(&csp_if_can, "csp_iface_t", NULL);
}

static PyMethodDef methods[] = {

    /* csp/csp.h */
    {"csp_init", pycsp_init, METH_VARARGS, ""},
    {"csp_set_address", pycsp_set_address, METH_VARARGS, ""},
    {"csp_get_address", pycsp_get_address, METH_NOARGS, ""},
    {"csp_set_hostname", pycsp_set_hostname, METH_O, ""},
    {"csp_get_hostname", pycsp_get_hostname, METH_NOARGS, ""},
    {"csp_set_model", pycsp_set_model, METH_O, ""},
    {"csp_get_model", pycsp_get_model, METH_NOARGS, ""},
    {"csp_set_revision", pycsp_set_revision, METH_O, ""},
    {"csp_get_revision", pycsp_get_revision, METH_NOARGS, ""},
    {"csp_socket", pycsp_socket, METH_VARARGS, ""},
    {"csp_accept", pycsp_accept, METH_VARARGS, ""},
    {"csp_read", pycsp_read, METH_VARARGS, ""},
    {"csp_send", pycsp_send, METH_VARARGS, ""},
    {"csp_transaction", pycsp_transaction, METH_VARARGS, ""},
    {"csp_recvfrom", pycsp_recvfrom, METH_VARARGS, ""},
    {"csp_sendto", pycsp_sendto, METH_VARARGS, ""},
    {"csp_sendto_reply", pycsp_sendto_reply, METH_VARARGS, ""},
    {"csp_connect", pycsp_connect, METH_VARARGS, ""},
    {"csp_close", pycsp_close, METH_O, ""},
    {"csp_conn_dport", pycsp_conn_dport, METH_O, ""},
    {"csp_conn_sport", pycsp_conn_sport, METH_O, ""},
    {"csp_conn_dst", pycsp_conn_dst, METH_O, ""},
    {"csp_conn_src", pycsp_conn_src, METH_O, ""},
    {"csp_listen", pycsp_listen, METH_VARARGS, ""},
    {"csp_bind", pycsp_bind, METH_VARARGS, ""},
    {"csp_route_start_task", pycsp_route_start_task, METH_VARARGS, ""},
    {"csp_route_work", pycsp_route_work, METH_VARARGS, ""},
    {"csp_ping", pycsp_ping, METH_VARARGS, ""},
    {"csp_ping_noreply", pycsp_ping_noreply, METH_VARARGS, ""},
    {"csp_reboot", pycsp_reboot, METH_VARARGS, ""},
    {"csp_shutdown", pycsp_shutdown, METH_VARARGS, ""},
    {"csp_rdp_set_opt", pycsp_rdp_set_opt, METH_VARARGS, ""},
    {"csp_rdp_get_opt", pycsp_rdp_get_opt, METH_NOARGS, ""},
    {"csp_conn_print_table", pycsp_conn_print_table, METH_NOARGS, ""},

    /* csp/csp_rtable.h */
    {"csp_rtable_set", pycsp_rtable_set, METH_VARARGS, ""},
    {"csp_rtable_print", pycsp_rtable_print, METH_NOARGS, ""},
    {"csp_rtable_clear", pycsp_rtable_clear, METH_NOARGS, ""},

    /* csp/csp_buffer.h */
    {"csp_buffer_init", pycsp_buffer_init, METH_VARARGS, ""},
    {"csp_buffer_free", pycsp_buffer_free, METH_VARARGS, ""},
    {"csp_buffer_remaining", pycsp_buffer_remaining, METH_NOARGS, ""},
    {"csp_buffer_size", pycsp_buffer_size, METH_NOARGS, ""},

    /* csp/csp_buffer.h */
    {"csp_cmp_clock", pycsp_cmp_clock, METH_VARARGS, ""},
    {"csp_cmp_ident", pycsp_cmp_ident, METH_VARARGS, ""},
    {"csp_cmp_peek", pycsp_cmp_peek, METH_VARARGS, ""},
    {"csp_cmp_poke", pycsp_cmp_poke, METH_VARARGS, ""},

    /* csp/interfaces/csp_if_zmqhub.h */
    {"csp_zmqhub_init", pycsp_zmqhub_init, METH_VARARGS, ""},

    /* csp/interfaces/csp_if_can.h */
    {"csp_can_init", pycsp_can_init, METH_VARARGS, ""},

    /* helpers */
    {"packet_length", pycsp_packet_length, METH_O, ""},
    {"packet_data", pycsp_packet_data, METH_O, ""},
    {"csp_zmqhub_if", pycsp_zmqhub_if, METH_NOARGS, ""},
    {"csp_can_if", pycsp_can_if, METH_NOARGS, ""},

    /* sentinel */
    {NULL, NULL, 0, NULL}
};

#ifdef IS_PY3
static struct PyModuleDef moduledef = {
    PyModuleDef_HEAD_INIT,
    "libcsp_py3",
    NULL, /* module documentation, may be NULL */
    -1,       /* size of per-interpreter state of the module,
                 or -1 if the module keeps state in global variables. */
    methods,
    NULL,
    NULL,
    NULL,
    NULL
};
#endif

#ifdef IS_PY3
PyMODINIT_FUNC PyInit_libcsp_py3(void) {
#else
    PyMODINIT_FUNC initlibcsp_py2(void) {
#endif

        PyObject* m;

#ifdef IS_PY3
        m = PyModule_Create(&moduledef);
#else
        m = Py_InitModule("libcsp_py2", methods);
#endif
        /**
         * csp/csp_types.h
         */

        /* RESERVED PORTS */
        PyModule_AddIntConstant(m, "CSP_CMP", CSP_CMP);
        PyModule_AddIntConstant(m, "CSP_PING", CSP_PING);
        PyModule_AddIntConstant(m, "CSP_PS", CSP_PS);
        PyModule_AddIntConstant(m, "CSP_MEMFREE", CSP_MEMFREE);
        PyModule_AddIntConstant(m, "CSP_REBOOT", CSP_REBOOT);
        PyModule_AddIntConstant(m, "CSP_BUF_FREE", CSP_BUF_FREE);
        PyModule_AddIntConstant(m, "CSP_UPTIME", CSP_UPTIME);
        PyModule_AddIntConstant(m, "CSP_ANY", CSP_MAX_BIND_PORT + 1);
        PyModule_AddIntConstant(m, "CSP_PROMISC", CSP_MAX_BIND_PORT + 2);

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

        /**
	 * csp/csp_error.h
	 */

        PyModule_AddIntConstant(m, "CSP_ERR_NONE", CSP_ERR_NONE);

        /* SOCKET OPTIONS */

        /* CONNECT OPTIONS */

        /**
         * csp/rtable.h
         */
        PyModule_AddIntConstant(m, "CSP_NODE_MAC", CSP_NODE_MAC);

        /**
         * csp/interfaces/csp_if_can.h
         */
        PyModule_AddIntConstant(m, "CSP_CAN_MASKED", CSP_CAN_MASKED);
        PyModule_AddIntConstant(m, "CSP_CAN_PROMISC", CSP_CAN_PROMISC);

#ifdef IS_PY3
        return m;
#endif
    }

