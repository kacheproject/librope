
#include <rope.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <asprintf.h>

#define NonNullOrGoToErrCleanup(v)                                             \
    if (!v)                                                                    \
    goto errcleanup

#define New(type) malloc(sizeof(type))

static char *endpoint_replace_port(const char *endpoint, int port){
    size_t slen = strlen(endpoint);
    size_t port_start_index = 0;
    for (size_t i=0; i<slen; i++){
        if (endpoint[i] == ':'){
            port_start_index = i+1;
            break;
        }
    }
    if (port_start_index == 0){
        return NULL;
    }
    char *port_str = NULL;
    asprintf(&port_str, "%d", port);
    if (!port_str){
        return NULL;
    }
    size_t port_slen = strlen(port_str);
    size_t new_slen = port_start_index - 1 + port_slen + 1; /* term \0 included */
    char *result = malloc(new_slen * sizeof(char));
    memset(result, 0, new_slen);
    if (!result){
        free(port_str);
        return NULL;
    }
    for (size_t i=0; i<port_start_index; i++){
        result[i] = endpoint[i];
    }
    for (size_t i=0; i<port_slen; i++){
        result[i] = port_str[i];
    }
    free(port_str);
    return result;
}

/* Router */

rope_router *rope_router_init(rope_router *self, rwtp_frame *self_id,
                              rwtp_frame *network_key) {
    khash_t(ptr) *pins = kh_init(ptr);
    NonNullOrGoToErrCleanup(pins);
    zpoller_t *poller = zpoller_new(NULL);
    NonNullOrGoToErrCleanup(poller);
    *self = (struct rope_router){
        .self_id = self_id,
        .network_key = network_key,
        .pins = pins,
        .poller = poller,
    };
    return self;

errcleanup:
    if (pins) {
        kh_destroy(ptr, pins);
    }
    if (poller) {
        zpoller_destroy(&poller);
    }
    return NULL;
}

void rope_router_deinit(rope_router *self) {
    rope_pin *pin;
    kh_foreach_value(self->pins, pin, rope_pin_destroy(pin));
    zpoller_destroy(&self->poller);
    kh_destroy(ptr, self->pins);
    rwtp_frame_destroy(self->network_key);
    rwtp_frame_destroy(self->self_id);
}

rope_router *rope_router_new(rwtp_frame *self_id, rwtp_frame *network_key) {
    rope_router *object = New(rope_router);
    if (!object) {
        return NULL;
    }
    if (!rope_router_init(object, self_id, network_key)) {
        free(object);
    }
    return object;
}

void rope_router_destroy(rope_router *self) {
    rope_router_deinit(self);
    free(self);
}

static int rope_wire_type_to_zmq_type(rope_sock_type type) {
    switch (type) {
    case ROPE_SOCK_P2P:
        return ZMQ_DEALER;
    case ROPE_SOCK_PUB:
        return ZMQ_PUB;
    case ROPE_SOCK_SUB:
        return ZMQ_SUB;
    };
}

/* Wire */

rope_wire *rope_wire_init(rope_wire *self, char *address, rope_sock_type type,
                          zsock_t *sock, zactor_t *monitor,
                          rwtp_session *session) {
    if (!sock) {
        sock = zsock_new(rope_wire_type_to_zmq_type(type));
        NonNullOrGoToErrCleanup(sock);
    }
    if (!monitor) {
        monitor = zactor_new(zmonitor, sock);
        NonNullOrGoToErrCleanup(monitor);
    }
    NonNullOrGoToErrCleanup(session);
    *self = (struct rope_wire){
        .address = address,
        .type = type,
        .sock = sock,
        .monitor = monitor,
        .session = session,
    };
    return self;

errcleanup:
    if (address)
        free(address);
    if (sock)
        zsock_destroy(&sock);
    if (monitor)
        zactor_destroy(&monitor);
    if (session)
        rwtp_session_destroy(session);
    return NULL;
}

rope_wire *rope_wire_new(zsock_t *sock, char *address, rope_sock_type type,
                         zactor_t *monitor, rwtp_session *session) {
    rope_wire *object = New(rope_wire);
    if (!object)
        return NULL;
    if (!rope_wire_init(object, address, type, sock, monitor, session)) {
        return NULL;
    }
    return object;
}

void rope_wire_deinit(rope_wire *self) {
    free(self->address);
    zactor_destroy(&self->monitor);
    zsock_destroy(&self->sock);
    rwtp_session_destroy(self->session);
}

void rope_wire_destroy(rope_wire *self) {
    rope_wire_deinit(self);
    free(self);
}

rope_wire *rope_wire_new_connect(char *endpoint, rope_sock_type type, rwtp_frame *network_key){
    NonNullOrGoToErrCleanup(network_key);
    zsock_t *sock = zsock_new(rope_wire_type_to_zmq_type(type));
    int port;
    if ((port = zsock_connect(sock, endpoint)) < 0){
        goto errcleanup;
    }
    char *complete_endpoint = endpoint_replace_port(endpoint, port);
    NonNullOrGoToErrCleanup(complete_endpoint);
    rwtp_session *session = rwtp_session_new(network_key);
    NonNullOrGoToErrCleanup(session);
    rwtp_frame_destroy(network_key); network_key = NULL;

    rope_wire *wire = rope_wire_new(sock, complete_endpoint, type, NULL, session);
    NonNullOrGoToErrCleanup(wire);
    free(endpoint); endpoint = NULL;
    return wire;

    errcleanup:
    if (endpoint) free(endpoint);
    if (sock) zsock_destroy(&sock);
    if (session) rwtp_session_destroy(session);
    if (network_key) rwtp_frame_destroy(network_key);
    if (complete_endpoint) free(complete_endpoint);
    return NULL;
}

rope_wire *rope_wire_new_bind(char *endpoint, rope_sock_type type, rwtp_frame *network_key){
    NonNullOrGoToErrCleanup(network_key);
    zsock_t *sock = zsock_new(rope_wire_type_to_zmq_type(type));
    int port;
    if ((port = zsock_bind(sock, endpoint)) < 0){
        goto errcleanup;
    }
    char *complete_endpoint = endpoint_replace_port(endpoint, port);
    NonNullOrGoToErrCleanup(complete_endpoint);
    rwtp_session *session = rwtp_session_new(network_key);
    NonNullOrGoToErrCleanup(session);
    rwtp_frame_destroy(network_key); network_key = NULL;

    rope_wire *wire = rope_wire_new(sock, complete_endpoint, type, NULL, session);
    NonNullOrGoToErrCleanup(wire);
    free(endpoint); endpoint = NULL;
    return wire;

    errcleanup:
    if (endpoint) free(endpoint);
    if (sock) zsock_destroy(&sock);
    if (session) rwtp_session_destroy(session);
    if (network_key) rwtp_frame_destroy(network_key);
    if (complete_endpoint) free(complete_endpoint);
    return NULL;
}

/* Pin */
rope_pin *rope_pin_init(rope_pin *self, rope_router *router,
                        char *proxy_binding_addr, rope_sock_type type) {
    khash_t(str) *wires = kh_init(str);
    NonNullOrGoToErrCleanup(wires);
    rope_sock_type proxy_type = type;
    if (type == ROPE_SOCK_PUB) {
        proxy_type = ROPE_SOCK_SUB;
    } else if (type == ROPE_SOCK_SUB) {
        proxy_type = ROPE_SOCK_PUB;
    }
    rope_wire *proxy = rope_wire_new_bind(proxy_binding_addr, proxy_type, rwtp_frame_clone(router->network_key));
    NonNullOrGoToErrCleanup(proxy);

    *self = (struct rope_pin){
        .router = router,
        .wires = wires,
        .proxy = proxy,
        .remote_id = NULL,
        .selected_wire = NULL,
    };
    return self;

errcleanup:
    if (proxy_binding_addr)
        free(proxy_binding_addr);
    if (wires)
        kh_destroy(str, wires);
    if (proxy)
        rope_wire_destroy(proxy);
    return NULL;
}

void rope_pin_deinit(rope_pin *self) {
    {
        rope_wire *wire;
        kh_foreach_value(self->wires, wire, rope_wire_destroy(wire));
    }
    kh_destroy(str, self->wires);
    rope_wire_destroy(self->proxy);
    *self = (struct rope_pin){};
}

rope_pin *rope_pin_new(rope_router *router, char *proxy_binding_addr,
                       rope_sock_type type) {
    rope_pin *object = New(rope_pin);
    if (!object)
        return NULL;
    if (!rope_pin_init(object, router, proxy_binding_addr, type)) {
        free(object);
        return NULL;
    }
    return object;
}

void rope_pin_destroy(rope_pin *self) {
    rope_pin_deinit(self);
    free(self);
}
