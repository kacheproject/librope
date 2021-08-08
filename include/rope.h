#include <rwtp.h>
#include <czmq.h>
#include "khash.h"

KHASH_MAP_INIT_STR(str, khptr_t);
KHASH_MAP_INIT_PTR(ptr, khptr_t);

typedef enum rope_sock_type {
    ROPE_SOCK_P2P,
    ROPE_SOCK_PUB,
    ROPE_SOCK_SUB,
} rope_sock_type;

typedef struct rope_router {
    rwtp_frame *self_id;
    khash_t(ptr) *pins; // zsock_t * or zactor_t * to rope_pin *
    zpoller_t *poller;
    rwtp_frame *network_key;
    zactor_t *poll_actor;
} rope_router;

rope_router *rope_router_init(rope_router *self, rwtp_frame *self_id, rwtp_frame *network_key);
void rope_router_deinit(rope_router *self);
rope_router *rope_router_new(rwtp_frame *self_id, rwtp_frame *network_key);
void rope_router_destroy(rope_router *self);

int rope_router_poll(rope_router *self, int timeout);
int rope_router_start_poll_thread(rope_router *self);
void rope_router_stop_poll_thread(rope_router *self);

int rope_router_connect(rope_router *self);

typedef struct rope_wire_state {
    uint64_t last_active_time;
    uint64_t inactive_timepoint;
    uint64_t active_timeout;
    double latency;
    int8_t handshake_stage;
} rope_wire_state;

typedef struct rope_wire {
    char *address;
    rope_sock_type type;
    zsock_t *sock;
    zactor_t *monitor;
    rwtp_session *session;
    rope_wire_state state;
} rope_wire;

/*! @function
    @abstract Setup structure for rope_wire. Callee owns arguments.
    @param self The memory pointer points to the memory need setting up.
    @param address The address related to the socket.
    @param type The rope socket type.
    @param sock CZMQ socket object. If it's NULL, new one will be created. Rope_wire does not do any binding or connecting operation on the socket.
    @param monitor CZMQ monitor actor. If it's NULL, new one which monitor `sock` will be created.
    @param session RWTP session. It must be non-NULL.
    @return self. NULL if any failed, and all arguments will be destroied properly. */
rope_wire *rope_wire_init(rope_wire *self, char *address, rope_sock_type type, zsock_t *sock, zactor_t *monitor, rwtp_session *session);

/*! @function
    @abstract Create a new rope_wire on heap and initialise. Callee owns arguments. See rope_wire_init for argument explaintion. 
    @param address The address related to the socket.
    @param type The rope socket type.
    @param sock CZMQ socket object. If it's NULL, new one will be created. Rope_wire does not do any binding or connecting operation on the socket.
    @param monitor CZMQ monitor actor. If it's NULL, new one which monitor `sock` will be created.
    @param session RWTP session. It must be non-NULL.
    @return rope_wire* The object created. NULL if any failed, and all arguments will be destroied properly.
    */
rope_wire *rope_wire_new(zsock_t *sock, char *address, rope_sock_type type, zactor_t *monitor, rwtp_session *session);

void rope_wire_deinit(rope_wire *self);
void rope_wire_destroy(rope_wire *self);

rope_wire *rope_wire_new_connect(char *endpoint, rope_sock_type type, rwtp_frame *network_key);
rope_wire *rope_wire_new_bind(char *endpoint, rope_sock_type type, rwtp_frame *network_key);

void rope_wire_set_active(rope_wire *self);
bool rope_wire_is_active(rope_wire *self);

void rope_wire_start_handshake(rope_wire *self, bool rolling);
bool rope_wire_is_handshake_completed(rope_wire *self);

int rope_wire_send(rope_wire *self, const rwtp_frame *msg);
rwtp_frame *rope_wire_recv_advanced(rope_wire *self, zsock_t *possible_sock);
rwtp_frame *rope_wire_recv(rope_wire *self);

int rope_wire_zpoller_add(rope_wire *self, zpoller_t *poller);
int rope_wire_zpoller_rm(rope_wire *self, zpoller_t *poller);

int rope_wire_input(rope_wire *self, zsock_t *input);
int rope_wire_output(rope_wire *self, zsock_t *output);

typedef struct rope_pin {
    rope_router *router;
    rwtp_frame *remote_id;
    khash_t(str) *wires; // char * to rope_wire *
    rope_wire *proxy; 
    rope_wire *selected_wire;
} rope_pin;

rope_pin *rope_pin_init(rope_pin *self, rope_router *router, char *proxy_binding_addr, rope_sock_type type);
void rope_pin_deinit(rope_pin *self);
rope_pin *rope_pin_new(rope_router *router, char *proxy_binding_addr, rope_sock_type type);
void rope_pin_destroy(rope_pin *self);

void rope_pin_merge(rope_pin *self, rope_pin *src);

/* Extension to rwtp library */

/* Return a pointer to rwtp_frame with data of uuid. Callee owns the argument. Caller owns the result.*/
rwtp_frame *rwtp_frame_from_zuuid(zuuid_t **uuid);

/* Return a zuuid_t * with uuid in self. Caller owns the argument and the result. */
zuuid_t *rwtp_frame_to_zuuid(rwtp_frame *self);

zmsg_t *rwtp_frame_to_zmsg(const rwtp_frame *self);
rwtp_frame *rwtp_frame_from_zmsg(zmsg_t *zmsg);

zframe_t *rwtp_frame_to_zframe(const rwtp_frame *self);
rwtp_frame *rwtp_frame_from_zframe(const zframe_t *f);
