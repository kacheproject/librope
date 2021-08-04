#include <tau/tau.h>
#include <rope.h>

TAU_MAIN()

TEST(rope, working_with_one_socket){
    int ret;
    zuuid_t *alice_id_z = zuuid_new();
    rwtp_frame *alice_id = rwtp_frame_from_zuuid(&alice_id_z);
    zuuid_t *bob_id_z = zuuid_new();
    rwtp_frame *bob_id = rwtp_frame_from_zuuid(&bob_id_z);
    rwtp_frame *network_key = rwtp_frame_gen_network_key();
    REQUIRE(network_key);
    REQUIRE(alice_id);
    REQUIRE(bob_id);

    rope_router *alice_router = rope_router_new(alice_id, network_key);
    REQUIRE(alice_router);
    rope_router *bob_router = rope_router_new(bob_id, network_key);
    REQUIRE(bob_router);
    rwtp_frame_destroy(alice_id);
    rwtp_frame_destroy(bob_id);
    rwtp_frame_destroy(network_key);
    rope_router_start_poll_thread(alice_router);
    rope_router_start_poll_thread(bob_router);

    /* Alice's turn */
    rope_wire *alice2bob_wire = rope_wire_new(alice_router, "tcp://127.0.0.1:7000", ZMQ_DEALER);
    REQUIRE(alice2bob_wire);
    ret = rope_wire_bind_peer(alice2bob_wire, "tcp://127.0.0.1:54173");
    REQUIRE_GE(ret, 0);

    /* Bob's turn */
    rope_wire *bob2alice_wire = rope_wire_new(bob_router, "tcp://127.0.0.1:7001", ZMQ_DEALER);
    ret = rope_wire_connect_peer(bob2alice_wire, "tcp://127.0.0.1:54173");
    REQUIRE_GE(ret, 0);

    zsock_t *alicei = zsock_new_dealer("tcp://127.0.0.1:7000");
    zsock_t *bobi = zsock_new_dealer("tcp://127.0.0.1:7001");

    zstr_send(alicei, "HELLO");
    zpoller_t *poller = zpoller_new(alicei, bobi, NULL);
    zpoller_wait(poller, -1);
    char *result = zstr_recv(bobi);
    REQUIRE_STREQ(result, "HELLO");
    zstr_free(&result);

    zpoller_destroy(&poller);
    rope_router_destroy(alice_router);
    rope_router_destroy(bob_router);
}
