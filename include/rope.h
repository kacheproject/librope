#include <rwtp.h>
#include <czmq.h>
#include "khash.h"

KHASH_MAP_INIT_STR(str, khptr_t);
KHASH_MAP_INIT_PTR(ptr, khptr_t);

static const int RWTP_EOPTS_ROPE_ID = 64;

typedef void (*rope_cb_basefn)(void *udata);

typedef struct rope_cb_table {
    khash_t(str) *vft;
} rope_cb_table;

typedef struct rope_cb {
    rope_cb_basefn callback;
    void *udata;
    struct rope_cb *next;
} rope_cb;

/* Initialise a rope_cb_table. */
rope_cb_table rope_cb_table_init();

/* Deinitialise a rope_cb_table. */
void rope_cb_table_deinit(rope_cb_table *self);

/* Add a callback into rope_cb_table. */
int rope_cb_table_set_callback(rope_cb_table *self, const char *name, rope_cb_basefn callback, void *udata);

/* A shortcut helps you cast `callback` as rope_cb_basefn.
The rope_cb_basefn used rather than void* because void* could not be converted to function pointer. */
#define rope_cb_table_set_callback_q(self, name, callback, udata) rope_cb_table_set_callback(self, name, (rope_cb_basefn)callback, udata)

/* Get the rope_cb objects. */
const rope_cb *rope_cb_table_get_callbacks(rope_cb_table *self, const char *name);

/* Shortcut to invoke single rope_cb *. `self` is the pointer, `cb_type` is callback function type.
Example:
    rope_cb *any;
    typedef void (*spam_callback_type)(void* udata, char *arg0, char *arg1);
    rope_cb_invoke(any, spam_callback_type, "HELLO", "WORLD");
The first argument will be field 'udata' in rope_cb.
*/
#define rope_cb_invoke(self, cb_type, ...) (((cb_type)self->callback)(self->udata, __VA_ARGS__))

/* Call callbacks in rope_cb_table. `self` is `rope_cb_table *`, name is `const char *name`, cb_type is callback function type.
Example:
    typedef void (*spam_callback_type)(void* udata, char *arg0, char *arg1);
    rope_cb_table *my_cb_table;
    rope_cb_table_call(my_cb_table, "rope.test_callback", spam_callback_type, "HELLO", "TANKMAN");
*/
#define rope_cb_table_call(self, name, cb_type, ...) {\
    rope_cb *__curr = (rope_cb *)rope_cb_table_get_callbacks(self, name);\
    while(__curr){\
        rope_cb_invoke(__curr, cb_type, __VA_ARGS__);\
        __curr = __curr->next;\
    }\
}

typedef enum rope_sock_type {
    ROPE_SOCK_P2P,
    ROPE_SOCK_PUB,
    ROPE_SOCK_SUB,
} rope_sock_type;

typedef struct rope_router {
    zuuid_t *self_id;
    khash_t(ptr) *pins; // zsock_t * or zactor_t * to rope_pin *
    zpoller_t *poller;
    rwtp_frame *network_key;
    zactor_t *poll_actor;
    rope_cb_table callbacks;
} rope_router;

typedef struct rope_wire_state {
    uint64_t last_active_time;
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
    rope_cb_table callbacks;
} rope_wire;

/* Callback for event remote_id_changed. The event will be called every SETOPT ROPE_ID received */
typedef void (*rope_wire_on_remote_id_changed)(void *udata, rope_wire *wire, zuuid_t *uuid);

/* Callback for event handshake_completed. The event will be called every handshake completed. */
typedef void (*rope_wire_on_handshake_completed)(void *udata, rope_wire *wire);

/* Callback for event remote_id_requested. The event will be called when remote ask for identity. You should provide one though uuid. */
typedef void (*rope_wire_on_remote_id_requested)(void *udata, rope_wire *wire, zuuid_t **uuid);

typedef struct rope_pin {
    rope_router *router;
    zuuid_t *remote_id;
    khash_t(str) *wires; // char * to rope_wire *
    khash_t(ptr) *sockets; // zsock_t * or zactor_t * to rope_wire *
    rope_wire *proxy;
    rope_wire *selected_wire;
    rope_cb_table callbacks;
} rope_pin;

rope_router *rope_router_init(rope_router *self, zuuid_t *self_id, rwtp_frame *network_key);
void rope_router_deinit(rope_router *self);
rope_router *rope_router_new(zuuid_t *self_id, rwtp_frame *network_key);
void rope_router_destroy(rope_router *self);

int rope_router_poll(rope_router *self, int timeout);
int rope_router_start_poll_thread(rope_router *self);
void rope_router_stop_poll_thread(rope_router *self);

int rope_router_connect(rope_router *self);

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

rope_pin *rope_pin_init(rope_pin *self, rope_router *router, char *proxy_binding_addr, rope_sock_type type);
void rope_pin_deinit(rope_pin *self);
rope_pin *rope_pin_new(rope_router *router, char *proxy_binding_addr, rope_sock_type type);
void rope_pin_destroy(rope_pin *self);

int rope_pin_transfer_wire(rope_pin *self, rope_wire *wire, rwtp_frame *dst_id);

/* Select a wire. Return NULL if no one fits. */
rope_wire *rope_pin_select_wire(rope_pin *self);

/* Handle input from sock. Return -EPERM if failed, -EAGAIN if could not could not proxy message. */
int rope_pin_handle(rope_pin *self, zsock_t *sock);

/* Add a rope_wire. Return the endpoint of the wire. Callee owns arguments. Callee owns the result.*/
const char * rope_pin_add_wire(rope_pin *self, rope_wire *wires);

/* Extension to rwtp library */

/* Return a pointer to rwtp_frame with data of uuid. Callee owns the argument. Caller owns the result.*/
rwtp_frame *rwtp_frame_from_zuuid(zuuid_t **uuid);

/* Return a zuuid_t * with uuid in self. Caller owns the argument and the result. */
zuuid_t *rwtp_frame_to_zuuid(rwtp_frame *self);

zmsg_t *rwtp_frame_to_zmsg(const rwtp_frame *self);
rwtp_frame *rwtp_frame_from_zmsg(zmsg_t *zmsg);

zframe_t *rwtp_frame_to_zframe(const rwtp_frame *self);
rwtp_frame *rwtp_frame_from_zframe(const zframe_t *f);
