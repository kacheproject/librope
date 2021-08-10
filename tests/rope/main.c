#include <tau/tau.h>
#include <rope.h>
#include "strdup.h"

TAU_MAIN()

TEST(rope_router, init_and_deinit){
    zuuid_t *uuid = zuuid_new();

    rope_router router0;
    rope_router_init(&router0, zuuid_dup(uuid), rwtp_frame_gen_network_key());
    REQUIRE_BUF_EQ((void *)zuuid_data(router0.self_id), (void *)zuuid_data(uuid), zuuid_size(uuid));
    rope_router_deinit(&router0);

    rope_router *router1 = rope_router_new(zuuid_dup(uuid), rwtp_frame_gen_network_key());
    REQUIRE_BUF_EQ((void *)zuuid_data(router1->self_id), (void *)zuuid_data(uuid), zuuid_size(uuid));
    rope_router_destroy(router1);

    zuuid_destroy(&uuid);
}

TEST(rope_router, poll_thread_start_and_stop){
    rope_router router0;
    zuuid_t *uuid = zuuid_new();
    rope_router_init(&router0, uuid, rwtp_frame_gen_network_key());
    rope_router_start_poll_thread(&router0);
    rope_router_stop_poll_thread(&router0);
    rope_router_deinit(&router0);
}

TEST(rope_wire, init_and_deinit){
    rope_wire *wire = rope_wire_new_bind(strdup("tcp://127.0.0.1:!"), ROPE_SOCK_P2P, rwtp_frame_gen_network_key());
    REQUIRE_STRNE(wire->address, "tcp://127.0.0.1:!"); /* rope_wire_new_{bind, connect} should replace the port with actual port. */
    rope_wire_destroy(wire);
}

TEST(rope_wire, p2p_wire){
    rwtp_frame *netkey = rwtp_frame_gen_network_key();
    rope_wire *alice = rope_wire_new_bind(strdup("tcp://127.0.0.1:!"), ROPE_SOCK_P2P, rwtp_frame_clone(netkey));
    rope_wire *bob = rope_wire_new_connect(strdup(alice->address), ROPE_SOCK_P2P, rwtp_frame_clone(netkey));
    rwtp_frame_destroy(netkey);

    zpoller_t *poller = zpoller_new(NULL);
    rope_wire_zpoller_add(alice, poller);
    rope_wire_zpoller_add(bob, poller);

    rope_wire_start_handshake(alice, false);

    while (!(rope_wire_is_handshake_completed(alice) && rope_wire_is_handshake_completed(bob))){
        zsock_t *sock = zpoller_wait(poller, -1);
        if (sock == alice->sock || sock == (zsock_t *)alice->monitor){
            rwtp_frame *user_message = rope_wire_recv_advanced(alice, sock);
            REQUIRE(!user_message);
        } else {
            rwtp_frame *user_message = rope_wire_recv_advanced(bob, sock);
            REQUIRE(!user_message);
        }
    }

    rwtp_frame hellof = {.iovec_len=7, .iovec_data="Hello!", .frame_next=NULL};
    rope_wire_send(alice, &hellof);
    rwtp_frame *recevied = rope_wire_recv(bob);
    REQUIRE_STREQ((char *)recevied->iovec_data, (char *)hellof.iovec_data);
    rwtp_frame_destroy(recevied);

    zpoller_destroy(&poller);
    rope_wire_destroy(alice);
    rope_wire_destroy(bob);
}

typedef void (*increment_callback_fn)(void *udata, char *arg0);

void increment_callback(void *udata, char *arg0){
    REQUIRE_STREQ(arg0, "Hello!");
    int *counter = udata;
    (*counter)++;
}

TEST(rope_cb_table, can_correctly_callback_funtions){
    int called_times = 0;
    rope_cb_table table = rope_cb_table_init();
    
    rope_cb_table_set_callback_q(&table, "test0", &increment_callback, &called_times);
    rope_cb_table_set_callback_q(&table, "test0", &increment_callback, &called_times);
    rope_cb_table_call(&table, "test0", increment_callback_fn, "Hello!");
    REQUIRE_EQ(called_times, 2);

    rope_cb_table_deinit(&table);
}

/* TODO: test if pin proxy working */
