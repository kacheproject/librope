
#include <rope.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <asprintf.h>
#include <zmq.h>

#define NonNullOrGoToErrCleanup(v)                                             \
    if (!v)                                                                    \
    goto errcleanup

#define New(type) malloc(sizeof(type))

static char *endpoint_replace_port(const char *endpoint, int port){
    size_t slen = strlen(endpoint);
    size_t port_start_index = 0;
    for (size_t i=0; i<slen; i++){
        if (endpoint[i] == ':' && endpoint[i+1] != '/'){
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
    size_t new_slen = port_start_index + port_slen + 1; /* term \0 included */
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
        result[i+port_start_index] = port_str[i];
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
        .state = (struct rope_wire_state){
            .active_timeout = 5,
            .handshake_stage = 0,
            .inactive_timepoint = 0,
            .last_active_time = 0,
            .latency = -1,
        },
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
    if (zsock_connect(sock, endpoint) < 0){
        zsys_error("rope_wire_new_connect: connect failed \"%s\"", endpoint);
        goto errcleanup;
    }
    rwtp_session *session = rwtp_session_new(network_key);
    NonNullOrGoToErrCleanup(session);
    rwtp_frame_destroy(network_key); network_key = NULL;

    rope_wire *wire = rope_wire_new(sock, endpoint, type, NULL, session);
    NonNullOrGoToErrCleanup(wire);
    return wire;

    errcleanup:
    if (endpoint) free(endpoint);
    if (sock) zsock_destroy(&sock);
    if (session) rwtp_session_destroy(session);
    if (network_key) rwtp_frame_destroy(network_key);
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

void rope_wire_set_active(rope_wire *self){
    if (self->type == ROPE_SOCK_P2P){
        self->state.active_timeout = 5;
    } else if (self->type == ROPE_SOCK_PUB){
        self->state.active_timeout = 0;
    } else if (self->type == ROPE_SOCK_SUB){
        self->state.active_timeout = 60;
    }
    self->state.last_active_time = time(NULL);
    self->state.inactive_timepoint = self->state.last_active_time + self->state.active_timeout;
}

bool rope_wire_is_active(rope_wire *self){
    if (self->state.active_timeout == 0) return true;
    return self->state.inactive_timepoint > self->state.last_active_time;
}

void rope_wire_start_handshake(rope_wire *self, bool rolling){
    if (rolling) self->state.handshake_stage = 0;
    if (self->state.handshake_stage != 0) return;
    if (self->type == ROPE_SOCK_P2P){
        rwtp_frame *prik = rwtp_frame_gen_private_key(), *iv = rwtp_frame_gen_public_key_mode_iv();
        rwtp_frame *set_pub_key_f = rwtp_session_send_set_pub_key(self->session, prik, iv);
        zmsg_t *set_pub_key_msg = rwtp_frame_to_zmsg(set_pub_key_f);
        rwtp_frame_destroy(set_pub_key_f);
        zmsg_send(&set_pub_key_msg, self->sock);
        rwtp_frame *ask_pub_key_f = rwtp_session_send_ask_option(self->session, RWTP_OPTS_PUBKEY);
        zmsg_t *ask_pub_key_msg = rwtp_frame_to_zmsg(ask_pub_key_f);
        rwtp_frame_destroy(ask_pub_key_f);
        zmsg_send(&ask_pub_key_msg, self->sock);
        self->state.handshake_stage += 1;
    } else if (self->type == ROPE_SOCK_PUB){
        rwtp_frame *seck = rwtp_frame_gen_secret_key();
        rwtp_frame *set_sec_key_f = rwtp_session_send_set_sec_key(self->session, seck);
        zmsg_t *msg = rwtp_frame_to_zmsg(set_sec_key_f);
        rwtp_frame_destroy(set_sec_key_f);
        zmsg_send(&msg, self->sock);
        self->state.handshake_stage += 1;
    }
}

bool rope_wire_is_handshake_completed(rope_wire *self){
    if (self->type == ROPE_SOCK_P2P){
        return self->state.handshake_stage >= 2;
    } else if (self->type == ROPE_SOCK_PUB){
        return true;
    } else if (self->type == ROPE_SOCK_SUB){
        return self->state.handshake_stage >= 1;
    }
}

static int __rope_wire_send_plain(rope_wire *self, const rwtp_frame *f) {
    rwtp_frame *curr = f;
    while (curr) {
        zframe_t *zf = rwtp_frame_to_zframe(curr);
        if (zf) {
            if(zframe_send(&zf, self->sock, 0)){
                zframe_destroy(&zf);
                return -1;
            }
        } else {
            return -1;
        }
        curr = curr->frame_next;
    }
}

int rope_wire_send(rope_wire *self, const rwtp_frame *msg){
    if (!rope_wire_is_handshake_completed(self)){
        rope_wire_start_handshake(self, false);
        return -EAGAIN;
    }
    rwtp_frame *f = rwtp_session_send(self, msg);
    if (__rope_wire_send_plain(self, f)){
        return -1;
    }
    rwtp_frame_destroy(f);
    return 0;
}

rwtp_frame *rope_wire_recv_advanced(rope_wire *self, zsock_t *possible_sock){
    if (!possible_sock || possible_sock == self->sock){
        zframe_t *zf = zframe_recv(self->sock);
        rwtp_frame *st = rwtp_frame_from_zframe(zf);
        zframe_destroy(&zf);
        rwtp_session_read_result result = rwtp_session_read(self->session, st);
        rwtp_frame_destroy(st);
        if (result.status_code == RWTP_DATA){
            return result.user_message;
        } else if (result.status_code == RWTP_SETOPT){
            if (result.opt == RWTP_OPTS_PUBKEY){
                if(!rope_wire_is_handshake_completed(self)){
                    self->state.handshake_stage++;
                } else {
                    rope_wire_start_handshake(self, true);
                }
            } else if(result.opt == RWTP_OPTS_SECKEY){
                if (!rope_wire_is_handshake_completed(self)) self->state.handshake_stage++;
            }
        } else if (result.status_code == RWTP_ASKOPT){
            if (result.opt == RWTP_OPTS_PUBKEY){
                if (!rope_wire_is_handshake_completed(self)){
                    rwtp_frame *prik = rwtp_frame_gen_private_key(), *iv = rwtp_frame_gen_public_key_mode_iv();
                    rwtp_frame *f = rwtp_session_send_set_pub_key(self->session, prik, iv);
                    __rope_wire_send_plain(self, f);
                    rwtp_frame_destroy(f);
                    self->state.handshake_stage++;
                } else {
                    rope_wire_start_handshake(self, true);
                }
            } else if(result.opt == RWTP_OPTS_SECKEY){
                rwtp_frame *seck = rwtp_frame_gen_secret_key();
                rwtp_frame *f = rwtp_session_send_set_sec_key(self->session, seck);
                __rope_wire_send_plain(self, f);
                rwtp_frame_destroy(f);
            } else if(result.opt == RWTP_OPTS_TIME){
                rwtp_frame *f = rwtp_session_send_set_time(self->session, f);
                __rope_wire_send_plain(self, f);
                rwtp_frame_destroy(f);
            }
        }
        return NULL;
    } else if (possible_sock == self->monitor){
        /* When connection status changed */
    }
}
rwtp_frame *rope_wire_recv(rope_wire *self){
    return rope_wire_recv_advanced(self, NULL);
}

int rope_wire_zpoller_add(rope_wire *self, zpoller_t *poller){
    if (zpoller_add(poller, self->sock)){
        return -1;
    }
    if (zpoller_add(poller, self->monitor)){
        return -1;
    }
}

int rope_wire_zpoller_rm(rope_wire *self, zpoller_t *poller){
    if (zpoller_remove(poller, self->sock)){
        return -1;
    }
    if (zpoller_remove(poller, self->monitor)){
        return -1;
    }
}

int rope_wire_input(rope_wire *self, zsock_t *input){
    zmsg_t *msg = zmsg_recv(input);
    if (!msg){
        return -1;
    }
    rwtp_frame *frames = rwtp_frame_from_zmsg(msg);
    zmsg_destroy(&msg);
    if (!frames){
        return -1;
    }
    if (rope_wire_send(self, frames)){
        return -1;
    }
    rwtp_frame_destroy(frames);
    return 0;
}

int rope_wire_output(rope_wire *self, zsock_t *output){
    rwtp_frame *frames = rope_wire_recv(self);
    if (frames){
        zmsg_t *msg = rwtp_frame_to_zmsg(frames);
        if (!msg){
            rwtp_frame_destroy(frames);
            return -1;
        }
        if (zmsg_send(&msg, output)){
            rwtp_frame_destroy(frames);
            return -1;
        }
        rwtp_frame_destroy(frames);
        return 0;
    } else {
        return -EAGAIN;
    }
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
