#include <rwtp.h>
#include <czmq.h>

typedef struct rope_router {
    rwtp_frame *self_id;
    zlistx_t *all_wires; /* rope_wire * */
    zhashx_t *wires; // zsock_t * or zactor_t * to rope_wire *
    zpoller_t *poller;
    rwtp_frame *network_key;
    zactor_t *poll_actor;
} rope_router;

typedef struct rope_wire {
    rope_router *router;
    rwtp_frame *remote_id;
    zhashx_t *p_wires; // char * to zsock_t *
    zhashx_t *monitors; // char * to zactor_t *
    zhashx_t *p_states; // char * to struct wire_physical_state * (internal structure)
    zsock_t *proxy;
    char *proxy_binding_address;
    int proxy_socket_type;
    zsock_t *selected_p_wire;
    void *selected_p_state;
    rwtp_session *selected_session;

    zhashx_t *sessions; // char * to rwtp_session *
    int_fast32_t _ref;
} rope_wire;

rope_router *rope_router_init(rope_router *self, const rwtp_frame *self_id, const rwtp_frame *network_key);
void rope_router_deinit(rope_router *self);
rope_router *rope_router_new(const rwtp_frame *self_id, const rwtp_frame *network_key);
void rope_router_destroy(rope_router *self);

int rope_router_poll(rope_router *self, int timeout);
int rope_router_start_poll_thread(rope_router *self);
void rope_router_stop_poll_thread(rope_router *self);

int rope_router_connect(rope_router *self);

rope_wire *rope_wire_init(rope_wire *self, rope_router *router, const char *proxy_binding_addr, int proxy_socket_type);
void rope_wire_deinit(rope_wire *self);
rope_wire *rope_wire_new(rope_router *router, const char *proxy_binding_addr, int proxy_socket_type);
void rope_wire_destroy(rope_wire *self);

int rope_wire_add_wire(rope_wire *self, const char *physical_addr, zsock_t *sock);
void rope_wire_remove_wire(rope_wire *self, const char *physical_addr);
int rope_wire_handle_message(rope_wire *self, zsock_t *sock);
int rope_wire_connect(rope_wire *self, const char *remote_address, int zmq_sock_type);
int rope_wire_bind(rope_wire *self, const char *address, int zmq_sock_type);

int rope_wire_connect_peer(rope_wire *self, const char *remote_address);

int rope_wire_bind_peer(rope_wire *self, const char *address);

int rope_wire_connect_pub(rope_wire *self, const char *remote_address);

int rope_wire_bind_sub(rope_wire *self, const char *address);

rope_wire *rope_wire_merge(rope_wire *self, rope_wire *src);

/* Extension to rwtp library */

/* Return a pointer to rwtp_frame with data of uuid. Callee owns the argument. Caller owns the result.*/
rwtp_frame *rwtp_frame_from_zuuid(zuuid_t **uuid){
    rwtp_frame *result = rwtp_frame_new(zuuid_size(*uuid), NULL);
    memcpy(result->iovec_data, zuuid_data(*uuid), zuuid_size(*uuid));
    zuuid_destroy(uuid);
    return result;
}

/* Return a zuuid_t * with uuid in self. Caller owns the argument and the result. */
zuuid_t *rwtp_frame_to_zuuid(rwtp_frame *self){
    assert(self->iovec_len==ZUUID_LEN);
    return zuuid_new_from(self->iovec_data);
}

zmsg_t *rwtp_frame_to_zmsg(const rwtp_frame *self);
rwtp_frame *rwtp_frame_from_zmsg(zmsg_t *zmsg);

zframe_t *rwtp_frame_to_zframe(const rwtp_frame *self);
rwtp_frame *rwtp_frame_from_zframe(const zframe_t *f);
