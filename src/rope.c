
#include <rope.h>
#include <stdbool.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

static const void *zhashx_lookupr(zhashx_t *self, const void *value) {
    const char *key = NULL;
    for (const char *curr_key = zhashx_first(self); curr_key;
         curr_key = zhashx_next(self)) {
        if (zhashx_lookup(self, curr_key) == value) {
            key = curr_key;
        }
    }
    return key;
}

struct wire_physical_state {
    int ways; /* -1 means single-way receiving communication, 1 means single-way
                 sending, 2 means two-way */
    time_t last_active_time;
    time_t expected_next_signal_received;
    time_t active_expired_timeout; /* 0 means always active */
    bool ignore_lag;
    double lag;
};

static bool
wire_physical_state_is_single_way_receiving(struct wire_physical_state *self) {
    return self->ways == -1;
}

static bool
wire_physical_state_is_single_way_sending(struct wire_physical_state *self) {
    return self->ways == 1;
}

static bool wire_physical_state_is_two_way(struct wire_physical_state *self) {
    return self->ways == 2;
}

static void wire_physical_state_set_active(struct wire_physical_state *self) {
    self->last_active_time = time(NULL);
    self->expected_next_signal_received =
        self->last_active_time + self->active_expired_timeout;
}

static double wire_physical_state_life(struct wire_physical_state *self) {
    if (self->last_active_time == 0 ||
        self->expected_next_signal_received == 0) {
        return 0;
    } else if (self->active_expired_timeout == 0) {
        return 1;
    }
    return (time(NULL) - self->expected_next_signal_received + 0.0) /
           (self->active_expired_timeout + 0.0);
}

static bool wire_physical_state_is_active(struct wire_physical_state *self) {
    return self->active_expired_timeout == 0 ||
           time(NULL) < self->expected_next_signal_received;
}

static void wire_physical_state_set_lag(struct wire_physical_state *self,
                                        float lag) {
    self->ignore_lag = false;
    self->lag = lag;
}

static struct wire_physical_state *
wire_physical_state_init(struct wire_physical_state *self, int ways,
                         time_t active_expired_timeout) {
    *self = (struct wire_physical_state){
        .ways = ways,
        .ignore_lag = true,
        .active_expired_timeout = active_expired_timeout,
    };
    return self;
}

static void wire_physical_state_deinit(struct wire_physical_state *self) {
    *self = (struct wire_physical_state){};
}

static struct wire_physical_state *
wire_physical_state_new(int ways, time_t active_expired_timeout) {
    struct wire_physical_state *object =
        malloc(sizeof(struct wire_physical_state));
    if (!object) {
        return NULL;
    }
    wire_physical_state_init(object, ways, active_expired_timeout);
    return object;
}

static void wire_physical_state_destroy(struct wire_physical_state *self) {
    wire_physical_state_deinit(self);
    free(self);
}

static void wire_physical_state_destructor(void **self) {
    wire_physical_state_destroy(*self);
    *self = NULL;
}

zframe_t *rwtp_frame_to_zframe(const rwtp_frame *self) {
    zframe_t *result = zframe_new(NULL, self->iovec_len);
    if (!result) {
        return NULL;
    }
    memcpy(zframe_data(result), self->iovec_data, self->iovec_len);
    return result;
}

rwtp_frame *rwtp_frame_from_zframe(const zframe_t *f) {
    rwtp_frame *result = rwtp_frame_new(zframe_size((zframe_t *)f), NULL);
    if (!result) {
        return NULL;
    }
    memcpy(result->iovec_data, zframe_data((zframe_t *)f), result->iovec_len);
    return result;
}

zmsg_t *rwtp_frame_to_zmsg(const rwtp_frame *self) {
    zmsg_t *result = zmsg_new();
    for (const rwtp_frame *curr = self; curr; curr = curr->frame_next) {
        zmsg_addmem(result, curr->iovec_data, curr->iovec_len);
    }
    return result;
}

rwtp_frame *rwtp_frame_from_zmsg(zmsg_t *zmsg) {
    rwtp_frame *head = NULL, *prev = NULL, *curr = NULL;
    for (zframe_t *f = zmsg_first(zmsg); f; f = zmsg_next(zmsg)) {
        curr = rwtp_frame_new(zframe_size(f), NULL);
        if (!curr) {
            if (head) {
                rwtp_frame_destroy_all(head);
            }
        }
        memcpy(curr->iovec_data, zframe_data(f), curr->iovec_len);
        if (!head) {
            head = curr;
        }
        if (prev) {
            prev->frame_next = curr;
        }
        prev = curr;
    }
    return head;
}

static void rope_wire_destructor(void **object) {
    rope_wire_destroy(*object);
    *object = NULL;
}

static void *pointer_copy(const void *ptr) { return (void *)ptr; }

static int zsock_comparator(const void *item0, const void *item1) {
    return (intptr_t)item0 - (intptr_t)item1;
}

static size_t zsock_hasher(const void *key) { return (intptr_t)key; }

static void zsock_or_zactor_destructor(void **object) {
    if (zactor_is(*object)) {
        zactor_destroy((zactor_t **)object);
    } else if (zsock_is(*object)) {
        zsock_destroy((zsock_t **)object);
    } else {
        zsys_error("zsock_or_zactor_destructor: did you feed something neither "
                   "zsock_t * or zactor_t * into hashtable? %p",
                   *object);
    }
}

static void do_nothing_destructor(void **object) { /* do nothing */
}

rope_router *rope_router_init(rope_router *self, const rwtp_frame *self_id,
                              const rwtp_frame *network_key) {
    rwtp_frame *self_id_copy = rwtp_frame_clone(self_id);
    if (!self_id_copy) {
        return NULL;
    }
    rwtp_frame *network_key_clone = rwtp_frame_clone(network_key);
    if (!network_key_clone) {
        return NULL;
    }
    zpoller_t *poller = zpoller_new(NULL);
    if (!poller) {
        rwtp_frame_destroy(self_id_copy);
        return NULL;
    }
    zhashx_t *wires = zhashx_new();
    if (!wires) {
        rwtp_frame_destroy(self_id_copy);
        zpoller_destroy(&poller);
        return NULL;
    }
    zlistx_t *all_wires = zlistx_new();
    if (!all_wires) {
        rwtp_frame_destroy(self_id_copy);
        zpoller_destroy(&poller);
        zhashx_destroy(&wires);
        return NULL;
    }
    *self = (struct rope_router){
        .self_id = self_id_copy,
        .poller = poller,
        .wires = wires,
        .network_key = network_key_clone,
        .all_wires = all_wires,
    };
    zhashx_set_destructor(self->wires, do_nothing_destructor);
    /* we should not destruct rope_wire when any physical wire removed */
    zhashx_set_key_destructor(self->wires, do_nothing_destructor);
    /* the z-objects in self->wires is managed by rope_wire */
    zhashx_set_key_duplicator(self->wires, pointer_copy);
    zhashx_set_key_comparator(self->wires, zsock_comparator);
    zhashx_set_key_hasher(self->wires, zsock_hasher);
    zlistx_set_comparator(self->all_wires, zsock_comparator);
    zlistx_set_destructor(self->all_wires, rope_wire_destructor);
    return self;
}

void rope_router_deinit(rope_router *self) {
    if (self->poll_actor) {
        rope_router_stop_poll_thread(self);
    }
    zlistx_destroy(&self->all_wires);
    rwtp_frame_destroy(self->self_id);
    zpoller_destroy(&self->poller);
    zhashx_destroy(&self->wires);
    rwtp_frame_destroy(self->network_key);
}

rope_router *rope_router_new(const rwtp_frame *self_id,
                             const rwtp_frame *network_key) {
    rope_router *self = malloc(sizeof(rope_router));
    if (!self) {
        return NULL;
    }
    return rope_router_init(self, self_id, network_key);
}

void rope_router_destroy(rope_router *self) {
    rope_router_deinit(self);
    free(self);
}

int rope_router_poll(rope_router *self, int timeout) {
    zsock_t *sock = zpoller_wait(self->poller, timeout);
    if (sock) {
        rope_wire *wire_object = zhashx_lookup(self->wires, sock);
        if (!wire_object){
            zsys_error("rope_router_poll: could not found rope_wire object for socket %p, recent endpoint %s.", sock, zsock_endpoint(sock));
            return -EPERM;
        }
        int handler_ret = rope_wire_handle_message(wire_object, sock);
        if (handler_ret) {
            return -EBADMSG;
        }
    } else if (zpoller_terminated(self->poller)){
        return -ETERM;
    } else {
        return -EAGAIN;
    }
    return 0;
}

static void rwtp_session_destructor(void **object) {
    rwtp_session_destroy(*object);
    *object = NULL;
}

rope_wire *rope_wire_init(rope_wire *self, rope_router *router,
                          const char *proxy_binding_addr,
                          int proxy_socket_type) {
    zhashx_t *p_wires = zhashx_new();
    if (!p_wires)
        return NULL;
    zhashx_t *monitors = zhashx_new();
    if (!monitors) {
        zhashx_destroy(&p_wires);
        return NULL;
    }
    zhashx_t *p_states = zhashx_new();
    if (!p_states) {
        zhashx_destroy(&p_wires);
        zhashx_destroy(&monitors);
        return NULL;
    }
    char *proxy_binding_addr_copy = strdup(proxy_binding_addr);
    if (!proxy_binding_addr_copy) {
        zhashx_destroy(&p_wires);
        zhashx_destroy(&monitors);
        zhashx_destroy(&p_states);
        return NULL;
    }
    zhashx_t *sessions = zhashx_new();
    if (!sessions) {
        zhashx_destroy(&p_wires);
        zhashx_destroy(&monitors);
        zhashx_destroy(&p_states);
        free(proxy_binding_addr_copy);
        return NULL;
    }
    *self = (struct rope_wire){
        .router = router,
        .proxy_binding_address = proxy_binding_addr_copy,
        .p_wires = p_wires,
        .p_states = p_states,
        .monitors = monitors,
        .proxy_socket_type = proxy_socket_type,
        .sessions = sessions,
        .proxy_using_port = -1,
    };
    zhashx_set_destructor(p_wires, zsock_or_zactor_destructor);
    zhashx_set_destructor(monitors, zsock_or_zactor_destructor);
    zhashx_set_destructor(p_states, wire_physical_state_destructor);
    zhashx_set_destructor(sessions, rwtp_session_destructor);
    {
        void *ret = zlistx_add_end(router->all_wires, self);
        if (!ret) {
            zsys_error("rope_wire_init: no memory.");
            zhashx_destroy(&p_wires);
            zhashx_destroy(&monitors);
            zhashx_destroy(&p_states);
            free(proxy_binding_addr_copy);
            *self = (struct rope_wire){};
            return NULL;
        }
    }
    return self;
}

void rope_wire_deinit(rope_wire *self) {
    for (char *p_wire_key = zhashx_first(self->p_wires); p_wire_key;
         p_wire_key = zhashx_next(self->p_wires)) {
        rope_wire_remove_wire(self, p_wire_key);
    }
    zhashx_destroy(&self->p_wires);
    zhashx_destroy(&self->monitors);
    zhashx_destroy(&self->sessions);
    zhashx_destroy(&self->p_states);
    free(self->proxy_binding_address);
    if (self->proxy) {
        zsock_destroy(&self->proxy);
    }
    *self = (struct rope_wire){};
}

rope_wire *rope_wire_new(rope_router *router, const char *proxy_binding_addr,
                         int proxy_socket_type) {
    rope_wire *object = malloc(sizeof(rope_wire));
    if (!rope_wire_init(object, router, proxy_binding_addr,
                        proxy_socket_type)) {
        free(object);
        return NULL;
    }
    return object;
}

void rope_wire_destroy(rope_wire *self) {
    rope_wire_deinit(self);
    free(self);
}

int rope_wire_add_wire(rope_wire *self, const char *physical_addr,
                       zsock_t *sock) {
    // TODO: open monitor only when using ipc:// and tcp://
    // as described in http://czmq.zeromq.org/czmq4-0:zmonitor
    zactor_t *monitor = zactor_new(zmonitor, sock);
    if (!monitor) {
        return -1;
    }
    rwtp_session *new_session = rwtp_session_new(self->router->network_key);
    struct wire_physical_state *state;
    if (zsock_type(sock) == ZMQ_DEALER) {
        state = wire_physical_state_new(2, 3);
    } else if (zsock_type(sock) == ZMQ_PUB) {
        state = wire_physical_state_new(1, 0);
    } else if (zsock_type(sock) == ZMQ_SUB) {
        state = wire_physical_state_new(-1, 60);
    } else {
        zsys_error("rope_wire_add_wire: unknown zmq socket type %s.",
                   zsock_type_str(sock));
        zactor_destroy(&monitor);
        return -1;
    }
    zstr_sendx(monitor, "LISTEN", "CONNECTED", "CONNECT_DELAYED",
               "CONNECT_RETRIED", "DISCONNECTED", NULL);
    zstr_send(monitor, "START");
    // TODO: check if sending failed
    zhashx_insert(self->p_states, physical_addr, state);
    zhashx_insert(self->p_wires, physical_addr, sock);
    zhashx_insert(self->monitors, physical_addr, monitor);
    zhashx_insert(self->router->wires, sock, self);
    zhashx_insert(self->router->wires, monitor, self);
    zhashx_insert(self->sessions, physical_addr, new_session);
    int poller_ret = zpoller_add(self->router->poller, sock);
    assert(!poller_ret); /* TODO: friendly handling */
    poller_ret = zpoller_add(self->router->poller, monitor);
    assert(!poller_ret);
    zsys_debug("rope_wire_add_wire: rope_wire %p added physical wire \"%s\", socket %p", self, physical_addr, sock);
    return 0;
}

void rope_wire_remove_wire(rope_wire *self, const char *physical_addr) {
    zactor_t *monitor = zhashx_lookup(self->monitors, physical_addr);
    if (monitor) {
        if (self->router->wires) { // first remove from router, remove from
                                   // self->monitors will trigger destructor
            zhashx_delete(self->router->wires, monitor);
        }
        zhashx_delete(self->monitors, physical_addr);
    }
    zsock_t *sock = zhashx_lookup(self->p_wires, physical_addr);
    if (sock) {
        if (self->router->wires) {
            zhashx_delete(self->router->wires, sock);
        }
        zhashx_delete(self->p_wires, physical_addr);
    }
    rwtp_session *session = zhashx_lookup(self->sessions, physical_addr);
    if (session) {
        zhashx_delete(self->sessions, physical_addr);
    }
    rwtp_session *state = zhashx_lookup(self->p_states, physical_addr);
    if (state) {
        zhashx_delete(self->p_states, physical_addr);
    }
}

static void rope_wire_select_p_wire(rope_wire *self) {
    char *best_p_addr = NULL;
    for (char *curr_k = zhashx_first(self->p_wires); curr_k;
         curr_k = zhashx_next(self->p_wires)) {
        if (!best_p_addr) {
            best_p_addr = curr_k;
        }
        struct wire_physical_state *state =
            zhashx_lookup(self->p_states, curr_k);
        if (state) {
            struct wire_physical_state *best_state =
                zhashx_lookup(self->p_states, best_p_addr);
            if (!best_state && wire_physical_state_is_active(state)) {
                best_p_addr = curr_k;
            } else if (best_state && wire_physical_state_life(best_state) >
                                         wire_physical_state_life(state)) {
                best_p_addr = curr_k;
            }
        } else {
            zsys_error("rope_wire_select_p_wire: physical address \"%s\" does not "
                       "have wire state, every physical wire should have state",
                       curr_k);
        }
    }
    zsys_info("rope_wire_select_p_wire: %p switch to \"%s\"", self,
              best_p_addr);
    self->selected_p_state = zhashx_lookup(self->p_states, best_p_addr);
    self->selected_p_wire = zhashx_lookup(self->p_wires, best_p_addr);
    self->selected_session = zhashx_lookup(self->sessions, best_p_addr);
}

static rwtp_session *rope_wire_get_session_by_socket(rope_wire *self,
                                                     zsock_t *sock) {
    const char *paddr = zhashx_lookupr(self->sessions, sock);
    return zhashx_lookup(self->sessions, paddr);
}

zsock_t *rope_wire_proxy(rope_wire *self) {
    if (!self->proxy) {
        zsys_info("rope_wire_proxy: initialising proxy for endpoint %s", self->proxy_binding_address);
        zsock_t *proxy = zsock_new(self->proxy_socket_type);
        int ret = zsock_bind(proxy, self->proxy_binding_address);
        if (ret != -1) {
            if (zhashx_insert(self->router->wires, proxy, self)){
                return NULL;
            }
            if(zpoller_add(self->router->poller, proxy)){
                zhashx_delete(self->router->wires, proxy);
                return NULL;
            }
            self->proxy = proxy;
            self->proxy_using_port = ret;
        } else {
            zsock_destroy(&proxy);
            zsys_warning("rope_wire_proxy: proxy socket lazy binding "
                         "failed for %s, return %d.",
                         self->proxy_binding_address, ret);
        }
    }
    return self->proxy;
}

static rwtp_frame *
rope_wire_handle_options_read_result(rope_wire *self,
                                     const rwtp_session_read_result *result,
                                     rwtp_session *session) {
    assert(result->status_code == RWTP_ASKOPT ||
           result->status_code == RWTP_SETOPT);
    if (result->status_code == RWTP_ASKOPT) {
        if (result->opt == RWTP_OPTS_PUBKEY) {
            if (rwtp_session_check_public_key_mode(session) ||
                rwtp_session_check_seal_mode(session)) {
                // TODO: conditional key rotating
                rwtp_frame *prikey = rwtp_frame_gen_private_key();
                rwtp_frame *iv = rwtp_frame_gen_public_key_mode_iv();
                rwtp_frame *result =
                    rwtp_session_send_set_pub_key(session, prikey, iv);
                rwtp_frame_destroy(prikey);
                rwtp_frame_destroy(iv);
                return result;
            } else {
                return NULL;
            }
        } else if (result->opt == RWTP_OPTS_SECKEY) {
            if (rwtp_session_check_secret_key_mode(session) ||
                rwtp_session_check_seal_mode(session)) {
                // TODO: conditional key rotating
                rwtp_frame *seckey = rwtp_frame_gen_secret_key();
                rwtp_frame *result =
                    rwtp_session_send_set_sec_key(session, seckey);
                rwtp_frame_destroy(seckey);
                return result;
            } else {
                return NULL;
            }
        } else if (result->opt == RWTP_OPTS_TIME) {
            return rwtp_session_send_set_time(session, time(NULL));
        } else {
            /* TODO: error handling */
            return NULL;
        }
    } else if (result->status_code == RWTP_SETOPT) {
        /* nothing to do currently */
        return NULL;
    } else {
        return NULL;
    }
}

static int rope_handshake_request(zsock_t *selected_p_wire,
                                      rwtp_session *selected_session, int zmq_sock_type) {
    if (zmq_sock_type == ZMQ_DEALER) {
        rwtp_frame *prikey = rwtp_frame_gen_private_key();
        rwtp_frame *iv = rwtp_frame_gen_public_key_mode_iv();
        rwtp_frame *set_pub_key_frame =
            rwtp_session_send_set_pub_key(selected_session, prikey, iv);
        rwtp_frame_destroy(prikey);
        rwtp_frame_destroy(iv);
        zframe_t *set_pub_key_zframe = rwtp_frame_to_zframe(set_pub_key_frame);
        zframe_send(&set_pub_key_zframe, selected_p_wire, 0);
        rwtp_frame_destroy(set_pub_key_frame);
        rwtp_frame *ask_pub_key_frame = rwtp_session_send_ask_option(
            selected_session, RWTP_OPTS_PUBKEY);
        zframe_t *ask_pub_key_zframe = rwtp_frame_to_zframe(ask_pub_key_frame);
        zframe_send(&ask_pub_key_zframe, selected_p_wire, 0);
    } else if (zmq_sock_type == ZMQ_SUB) {
        rwtp_frame *seckey = rwtp_frame_gen_secret_key();
        rwtp_frame *set_sec_key_frame =
            rwtp_session_send_set_sec_key(selected_session, seckey);
        rwtp_frame_destroy(seckey);
        zframe_t *set_sec_key_zframe = rwtp_frame_to_zframe(set_sec_key_frame);
        zframe_send(&set_sec_key_zframe, selected_p_wire, 0);
    } else {
        zsys_error("rope_handshake_request: unknown proxy socket type %d",
                   zmq_sock_type);
    }
    return 0;
}

int rope_wire_handle_message(rope_wire *self, zsock_t *sock) {
    zsys_info("rope_wire_handle_message");
    if (sock == rope_wire_proxy(self)) {
        if (wire_physical_state_life(self->selected_p_state) < 0.01) {
            rope_wire_select_p_wire(self);
        }
        if (rwtp_session_check_complete_mode(self->selected_session)) {
            zmsg_t *msg = zmsg_recv(sock);
            rwtp_frame *frames = rwtp_frame_from_zmsg(msg);
            rwtp_frame *packed_frame =
                rwtp_session_send(self->selected_session, frames);
            zmsg_destroy(&msg);
            rwtp_frame_destroy_all(frames);
            zframe_t *zpacked_frame = rwtp_frame_to_zframe(packed_frame);
            zframe_send(&zpacked_frame, self->selected_p_wire, 0);
            rwtp_frame_destroy(packed_frame);
        } else {
            zsys_debug("rope_wire_handle_message: start handshake.");
            rope_handshake_request(self->selected_p_wire, self->selected_session, zsock_type(sock));
        }
    } else if (zactor_is(sock)) {
        const char *physical_addr = zhashx_lookupr(self->monitors, sock);
        if (physical_addr) {
            struct wire_physical_state *state =
                zhashx_lookup(self->p_states, physical_addr);
            wire_physical_state_set_active(state);
            zmsg_t *message = zmsg_recv(sock);
            zmsg_print(message);
            // TODO: rolling secret key when anyone connected to PUB
            // TODO: P2P pattern (Dealer-Dealer) should be
            // one-endpoint-to-one-endpoint
            zmsg_destroy(&message);
        }
        rope_wire_select_p_wire(self);
    } else {
        rwtp_session *corresponding_session =
            rope_wire_get_session_by_socket(self, sock);
        /* proxy message */
        if (rope_wire_proxy(self)) {
            zframe_t *frame = zframe_recv(sock);
            rwtp_frame *frame_cp = rwtp_frame_from_zframe(frame);
            zframe_destroy(&frame);
            rwtp_session_read_result result =
                rwtp_session_read(corresponding_session, frame_cp);
            rwtp_frame_destroy(frame_cp);
            if (result.status_code >= 0) {
                if (rwtp_session_check_complete_mode(corresponding_session)) {
                    if (result.user_message) {
                        zmsg_t *msg = rwtp_frame_to_zmsg(result.user_message);
                        for (int tried = 4; tried > 0; tried--) {
                            if (!zmsg_send(&msg, self->proxy)) {
                                break;
                            } else {
                                zsys_warning(
                                    "rope_wire_handle_message: message proxy "
                                    "failed, %d try(or tries) left.",
                                    tried);
                            }
                        }
                        rwtp_frame_destroy_all(result.user_message);
                        zmsg_destroy(&msg);
                    }
                    rwtp_frame *reply = rope_wire_handle_options_read_result(
                        self, &result, corresponding_session);
                    if (reply) {
                        zframe_t *zreply = rwtp_frame_to_zframe(reply);
                        zframe_send(&zreply, sock, 0);
                        rwtp_frame_destroy(reply);
                    }
                } else {
                    rwtp_frame *reply = rope_wire_handle_options_read_result(
                        self, &result, corresponding_session);
                    if (reply) {
                        zframe_t *zreply = rwtp_frame_to_zframe(reply);
                        zframe_send(&zreply, sock, 0);
                        rwtp_frame_destroy(reply);
                    }
                }
            } else {
                zsys_info("rope_wire_handle_message: session read message failed, code %d", result.status_code);
                return -EBADMSG;
            }
        } else {
            zsys_warning(
                "rope_wire_handle_message: could not feed received message "
                "into proxy, proxy socket not found, message dropped.");
            return -EPERM;
        }
    }
    return 0;
}

int rope_wire_connect(rope_wire *self, const char *remote_address,
                      int zmq_sock_type) {
    zsock_t *sock = zsock_new(zmq_sock_type);
    if (!sock)
        return -1;
    if (zsock_connect(sock, remote_address)) {
        zsys_error("rope_wire_connect: endpoint %s invaild.", remote_address);
        zsock_destroy(&sock);
        return -1;
    }
    rope_wire_add_wire(self, remote_address, sock);
    return 0;
}

int rope_wire_bind(rope_wire *self, const char *address, int zmq_sock_type) {
    zsock_t *sock = zsock_new(zmq_sock_type);
    if (!sock)
        return -1;
    int port;
    if ((port = zsock_bind(sock, address)) < 0) {
        zsys_error("rope_wire_bind: endpoint %s invaild.", address);
        zsock_destroy(&sock);
        return -1;
    }
    if (rope_wire_add_wire(self, address, sock)) {
        zsock_destroy(&sock);
        return -1;
    }
    return port;
}

int rope_wire_connect_peer(rope_wire *self, const char *remote_address) {
    return rope_wire_connect(self, remote_address, ZMQ_DEALER);
}

int rope_wire_bind_peer(rope_wire *self, const char *address) {
    return rope_wire_bind(self, address, ZMQ_DEALER);
}

int rope_wire_connect_pub(rope_wire *self, const char *remote_address) {
    return rope_wire_connect(self, remote_address, ZMQ_SUB);
}

int rope_wire_bind_sub(rope_wire *self, const char *address) {
    return rope_wire_bind(self, address, ZMQ_PUB);
}

static void rope_router_poll_actor(zsock_t *pipe, void *args) {
    rope_router *router = args;
    zpoller_t *self_poller = zpoller_new(pipe, NULL);
    if (!self_poller){
        zsock_signal(pipe, -1);
        zsys_error("rope_router_poll_actor: could not initialise zpoller, exit.");
        return;
    }
    zsys_info("rope_router_poll_actor: started on router %p", router);
    zsock_signal(pipe, 0);
    while ((!zpoller_wait(self_poller, 0)) && (!zpoller_terminated(self_poller))) {
        int ret = rope_router_poll(router, 2000);
        if (ret == -ETERM){
            break;
        }
    }
    zpoller_destroy(&self_poller);
    zsys_info("rope_router_poll_actor: stopped on router %p", router);
}

int rope_router_start_poll_thread(rope_router *self) {
    self->poll_actor = zactor_new(rope_router_poll_actor, self);
    if (!self->poll_actor) {
        return -1;
    }
    return 0;
}

void rope_router_stop_poll_thread(rope_router *self) {
    zactor_destroy(&self->poll_actor);
    self->poll_actor = NULL;
}

rwtp_frame *rwtp_frame_from_zuuid(zuuid_t **uuid){
    rwtp_frame *result = rwtp_frame_new(zuuid_size(*uuid), NULL);
    memcpy(result->iovec_data, zuuid_data(*uuid), zuuid_size(*uuid));
    zuuid_destroy(uuid);
    return result;
}

zuuid_t *rwtp_frame_to_zuuid(rwtp_frame *self){
    assert(self->iovec_len==ZUUID_LEN);
    return zuuid_new_from(self->iovec_data);
}
