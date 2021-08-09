#include <tau/tau.h>
#include <rope.h>
#include "strdup.h"

TAU_MAIN()

TEST(rope_router, init_and_deinit){
    zuuid_t *uuid = zuuid_new();
    rwtp_frame *self_id = rwtp_frame_from_zuuid(&uuid);

    rope_router router0;
    rope_router_init(&router0, rwtp_frame_clone(self_id), rwtp_frame_gen_network_key());
    REQUIRE_BUF_EQ(router0.self_id->iovec_data, self_id->iovec_data, self_id->iovec_len);
    rope_router_deinit(&router0);

    rope_router *router1 = rope_router_new(rwtp_frame_clone(self_id), rwtp_frame_gen_network_key());
    REQUIRE_BUF_EQ(router1->self_id->iovec_data, self_id->iovec_data, self_id->iovec_len);
    rope_router_destroy(router1);

    rwtp_frame_destroy(self_id);
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
        if (sock == alice->sock || sock == alice->monitor){
            rwtp_frame *user_message = rope_wire_recv_advanced(alice, sock);
            REQUIRE(!user_message);
        } else {
            rwtp_frame *user_message = rope_wire_recv_advanced(bob, sock);
            REQUIRE(!user_message);
        }
    }

    zpoller_destroy(&poller);
    rope_wire_destroy(alice);
    rope_wire_destroy(bob);
}
