
#include <rope.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <asprintf.h>
#include <zmq.h>

#define NonNullOrGoToErrCleanup(v)                                             \
    if (!(v))                                                                    \
    goto errcleanup

#define New(type) malloc(sizeof(type))

rope_cb_table rope_cb_table_init(){
    return (struct rope_cb_table){
        .vft = kh_init(str),
    };
}

void rope_cb_table_deinit(rope_cb_table *self){
    {
        rope_cb *cb = NULL;
        kh_foreach_value(self->vft, cb, {
            rope_cb *curr = cb;
            while (curr){
                rope_cb *next = curr->next;
                free(curr);
                curr = next;
            }
        });
    }
    kh_destroy(str, self->vft);
}

int rope_cb_table_set_callback(rope_cb_table *self, const char *name, rope_cb_basefn callback, void *udata){
    rope_cb *cb_obj = New(rope_cb);
    if (!cb_obj) return -1;
    *cb_obj = (struct rope_cb){
        .callback = callback,
        .udata = udata,
        .next = NULL,
    };
    rope_cb *curr = (rope_cb *)rope_cb_table_get_callbacks(self, name);
    if (curr){
        while(curr->next){
            curr = curr->next;
        }
        curr->next = cb_obj;
    } else {
        int ret = -1;
        khiter_t k = kh_put(str, self->vft, name, &ret);
        if (ret == 1){ /* If the table never used before, try again. */
            k = kh_put(str, self->vft, name, &ret);
        } else if (ret){
            free(cb_obj);
            return -1;
        }
        kh_val(self->vft, k) = cb_obj;
    }
    return 0;
}

const rope_cb *rope_cb_table_get_callbacks(rope_cb_table *self, const char *name){
    khiter_t k = kh_get(str, self->vft, name);
    if (k == kh_end(self->vft)){
        return NULL;
    } else {
        return kh_val(self->vft, k);
    }
}

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

rope_router *rope_router_init(rope_router *self, zuuid_t *self_id,
                              rwtp_frame *network_key) {
    khash_t(ptr) *pins = kh_init(ptr);
    if (!pins){
        return NULL;
    }
    zpoller_t *poller = zpoller_new(NULL);
    if (!poller){
        kh_destroy(ptr, pins);
        return NULL;
    }
    *self = (struct rope_router){
        .self_id = self_id,
        .network_key = network_key,
        .pins = pins,
        .poller = poller,
    };
    return self;
}

void rope_router_deinit(rope_router *self) {
    rope_pin *pin;
    kh_foreach_value(self->pins, pin, rope_pin_destroy(pin));
    zpoller_destroy(&self->poller);
    kh_destroy(ptr, self->pins);
    rwtp_frame_destroy(self->network_key);
    zuuid_destroy(&self->self_id);
}

rope_router *rope_router_new(zuuid_t *self_id, rwtp_frame *network_key) {
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

int rope_router_poll(rope_router *self, int timeout) {
    zsock_t *sock = zpoller_wait(self->poller, timeout);
    if (!sock) {
        if (zpoller_terminated(self->poller)) {
            return -ETERM;
        } else {
            return -EAGAIN;
        }
    }
    khiter_t pin_iter = kh_get(ptr, self->pins, sock);
    if (pin_iter == kh_end(self->pins)) {
        return -ENOKEY;
    }
    if (rope_pin_handle(kh_val(self->pins, pin_iter), sock)) {
        return -EPERM;
    }
    return 0;
}

static void rope_router_poll_actor(zsock_t *pipe, void *arg){
    rope_router *self = arg;
    if(zpoller_add(self->poller, pipe)){
        zsock_signal(pipe, -1);
        return;
    }
    zsock_signal(pipe, 0);
    int ret;
    while (true){
        ret = rope_router_poll(self, -1);
        if (ret == -ENOKEY || ret == -ETERM){
            break;
        }
    }
    zpoller_remove(self->poller, pipe);
}

int rope_router_start_poll_thread(rope_router *self){
    if (self->poll_actor) return -EPERM;
    self->poll_actor = zactor_new(&rope_router_poll_actor, self);
    if (!self->poll_actor){
        return -EPERM;
    } else {
        return 0;
    }
}

void rope_router_stop_poll_thread(rope_router *self){
    if (!self->poll_actor) return;
    zactor_destroy(&self->poll_actor);
    self->poll_actor = NULL;
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
    rwtp_session *session = NULL;
    zsock_t *sock = NULL;
    NonNullOrGoToErrCleanup(network_key);
    sock = zsock_new(rope_wire_type_to_zmq_type(type));
    if (zsock_connect(sock, "%s", endpoint) < 0){
        zsys_error("rope_wire_new_connect: connect failed \"%s\"", endpoint);
        goto errcleanup;
    }
    session = rwtp_session_new(network_key);
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
    char *complete_endpoint = NULL;
    zsock_t *sock = NULL;
    rwtp_session *session = NULL;

    NonNullOrGoToErrCleanup(network_key);
    sock = zsock_new(rope_wire_type_to_zmq_type(type));
    int port;
    if ((port = zsock_bind(sock, "%s", endpoint)) < 0){
        goto errcleanup;
    }
    complete_endpoint = endpoint_replace_port(endpoint, port);
    NonNullOrGoToErrCleanup(complete_endpoint);
    session = rwtp_session_new(network_key);
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
}

bool rope_wire_is_active(rope_wire *self){
    if (self->state.active_timeout == 0) return true;
    return time(NULL) > (self->state.last_active_time + self->state.active_timeout);
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
    } else {
        return false;
    }
}

static int __rope_wire_send_plain(rope_wire *self, const rwtp_frame *f) {
    rwtp_frame *curr = (rwtp_frame *)f;
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
    return 0;
}

int rope_wire_send(rope_wire *self, const rwtp_frame *msg){
    if (!rope_wire_is_handshake_completed(self)){
        rope_wire_start_handshake(self, false);
        return -EAGAIN;
    }
    rwtp_frame *f = rwtp_session_send(self->session, msg);
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
                rwtp_frame *f = rwtp_session_send_set_time(self->session, time(NULL));
                __rope_wire_send_plain(self, f);
                rwtp_frame_destroy(f);
            }
        }
        return NULL;
    } else if (possible_sock == (zsock_t *)self->monitor){
        /* When connection status changed */
        return NULL;
    }
    return NULL;
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
    return 0;
}

int rope_wire_zpoller_rm(rope_wire *self, zpoller_t *poller){
    if (zpoller_remove(poller, self->sock)){
        return -1;
    }
    if (zpoller_remove(poller, self->monitor)){
        return -1;
    }
    return 0;
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
    khash_t(str) *wires = NULL;
    khash_t(ptr) *sockets = NULL;
    rope_wire *proxy = NULL;

    wires = kh_init(str);
    NonNullOrGoToErrCleanup(wires);
    sockets = kh_init(ptr);
    NonNullOrGoToErrCleanup(sockets);
    rope_sock_type proxy_type = type;
    if (type == ROPE_SOCK_PUB) {
        proxy_type = ROPE_SOCK_SUB;
    } else if (type == ROPE_SOCK_SUB) {
        proxy_type = ROPE_SOCK_PUB;
    }
    proxy = rope_wire_new_bind(proxy_binding_addr, proxy_type, rwtp_frame_clone(router->network_key));
    rope_wire_zpoller_add(proxy, router->poller);
    NonNullOrGoToErrCleanup(proxy);

    *self = (struct rope_pin){
        .router = router,
        .wires = wires,
        .sockets = sockets,
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
    if (sockets)
        kh_destroy(ptr, sockets);
    return NULL;
}

void rope_pin_deinit(rope_pin *self) {
    {
        rope_wire *wire;
        kh_foreach_value(self->wires, wire, rope_wire_zpoller_rm(wire, self->router->poller);rope_wire_destroy(wire));
    }
    kh_destroy(str, self->wires);
    rope_wire_zpoller_rm(self->proxy, self->router->poller);
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

rope_wire *rope_pin_select_wire(rope_pin *self){
    /* TODO: better wire-selecting algorithm */
    rope_wire *longest_uptime_wire = NULL;
    {
        rope_wire *curr = NULL;
        kh_foreach_value(self->wires, curr, {
            if (rope_wire_is_active(curr)){
                if (!longest_uptime_wire){
                    longest_uptime_wire = curr;
                } else if (longest_uptime_wire->state.last_active_time < curr->state.last_active_time){
                    longest_uptime_wire = curr;
                }
            }
        });
    }
    self->selected_wire = longest_uptime_wire;
    return longest_uptime_wire;
}

int rope_pin_handle(rope_pin *self, zsock_t *sock){
    if (sock == self->proxy->sock){
        if (!rope_pin_select_wire(self)){
            return -EAGAIN;
        }
        zmsg_t *msg = zmsg_recv(sock);
        if (!msg){
            return -EPERM;
        }
        rwtp_frame *frames = rwtp_frame_from_zmsg(msg);
        if (!frames){
            return -EPERM;
        }
        zmsg_destroy(&msg);
        if (rope_wire_send(self->selected_wire, frames)){
            return -EPERM;
        }
        rwtp_frame_destroy(frames);
    } else if (sock == (zsock_t *)self->proxy->monitor){
        /* Do nothing */
    } else {
        khiter_t wire_iter = kh_get(ptr, self->sockets, sock);
        if (wire_iter == kh_end(self->sockets)){
            return -EPERM;
        }
        rope_wire *wire = kh_val(self->sockets, wire_iter);
        rope_wire_set_active(wire);
        if (rope_wire_output(wire, self->proxy->sock)){
            return -EPERM;
        }
    }
    return 0;
}

const char * rope_pin_add_wire(rope_pin *self, rope_wire *wire){
    int ret;
    khiter_t k;
    k = kh_put(str, self->wires, wire->address, &ret);
    NonNullOrGoToErrCleanup(ret != -1);
    kh_val(self->wires, k) = wire;
    k = kh_put(ptr, self->sockets, wire->sock, &ret);
    NonNullOrGoToErrCleanup(ret != -1);
    kh_val(self->sockets, k) = wire;
    k = kh_put(ptr, self->sockets, wire->monitor, &ret);
    NonNullOrGoToErrCleanup(ret != -1);
    kh_val(self->sockets, k) = wire;
    NonNullOrGoToErrCleanup(!rope_wire_zpoller_add(wire, self->router->poller));
    return wire->address;

    errcleanup:
    if ((k = kh_get(str, self->wires, wire->address)) != kh_end(self->wires)) kh_del(str, self->wires, k);
    if ((k = kh_get(ptr, self->sockets, wire->sock)) != kh_end(self->wires)) kh_del(ptr, self->sockets, k);
    if ((k = kh_get(ptr, self->sockets, wire->monitor)) != kh_end(self->sockets)) kh_del(ptr, self->sockets, k);
    rope_wire_zpoller_rm(wire, self->router->poller);
    rope_wire_destroy(wire);
    return NULL;
}
