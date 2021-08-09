#include <tau/tau.h>
#include <rwtp.h>
#include <time.h>

TAU_MAIN()

TEST(rwtp_frame, rwtp_frames_can_be_init_and_deinit) {
    uint64_t i = UINT64_MAX;
    rwtp_frame frame;
    int init_ret = rwtp_frame_init(&frame, sizeof(uint64_t), NULL);
    REQUIRE_EQ(init_ret, 0);
    *(uint64_t*)frame.iovec_data = i;
    rwtp_frame_deinit(&frame);
}

TEST(rwtp_frame, rwtp_frame_init_will_not_alloc_memory_when_size_is_zero) {
    rwtp_frame frame;
    int init_ret = rwtp_frame_init(&frame, 0, NULL);
    REQUIRE_EQ(init_ret, 0);
    REQUIRE_EQ(frame.iovec_data, NULL);
}

TEST(rwtp_frame, rwtp_frame_init_will_set_frame_next) {
    rwtp_frame frame0, frame1;
    int init_ret = rwtp_frame_init(&frame0, 0, &frame1);
    REQUIRE_EQ(init_ret, 0);
    init_ret = rwtp_frame_init(&frame1, 0, NULL);
    REQUIRE(frame0.frame_next == &frame1);
}

TEST(rwtp_frame, rwtp_frame_deinit_all_can_deinitialise_all_chained_frames) {
    rwtp_frame frames[64];
    for (size_t i=0; i<64; i++){
        rwtp_frame_init(&(frames[i]), sizeof(char), NULL);
    }
    rwtp_frames_chain(frames, 64);
    rwtp_frame_deinit_all(frames);
    for (size_t i=0; i<64; i++){
        REQUIRE_EQ(frames[i].iovec_data, NULL);
    }
}

TEST(rwtp_frame, rwtp_frame_pack_frames_and_rwtp_frame_unpack_frames){
    rwtp_frame frames[2] = {
        {"Hello", sizeof(char)*6},
        {"World", sizeof(char)*6},
    };
    rwtp_frames_chain(frames, 2);
    rwtp_frame *blk = rwtp_frame_pack_frames(frames);
    rwtp_frame *unpacked = rwtp_frame_unpack_frames(blk);
    rwtp_frame_destroy(blk);
    CHECK_STREQ((char *)(unpacked->iovec_data), (char *)(frames[0].iovec_data));
    CHECK_STREQ((char *)(unpacked->frame_next->iovec_data), (char *)(frames[1].iovec_data));
    rwtp_frame_destroy_all(unpacked);
}

TEST(rwtp_session, rwtp_session_can_handshake_public_key_mode) {
    rwtp_session alice={}, bob={};
    rwtp_frame *network_key = rwtp_frame_gen_network_key();
    alice.network_key = rwtp_frame_clone(network_key);
    bob.network_key = rwtp_frame_clone(network_key);
    rwtp_frame_destroy(network_key);
    REQUIRE_TRUE(rwtp_session_check_seal_mode(&alice));
    REQUIRE_TRUE(rwtp_session_check_seal_mode(&bob));

    rwtp_frame *bob_private_key = rwtp_frame_gen_private_key();
    REQUIRE(bob_private_key != NULL);
    rwtp_frame *bob_iv = rwtp_frame_gen_public_key_mode_iv();
    REQUIRE(bob_iv != NULL);
    rwtp_frame *bob_set_pub_keyf = rwtp_session_send_set_pub_key(&bob, bob_private_key, bob_iv);
    rwtp_session_read_result alice_set_pub_key_received = rwtp_session_read(&alice, bob_set_pub_keyf);
    rwtp_frame_destroy(bob_set_pub_keyf);
    REQUIRE(alice_set_pub_key_received.status_code == RWTP_SETOPT);
    REQUIRE(alice_set_pub_key_received.opt == RWTP_OPTS_PUBKEY);

    rwtp_frame *bob_ask_pub_keyf = rwtp_session_send_ask_option(&bob, RWTP_OPTS_PUBKEY);
    rwtp_session_read_result alice_ask_pub_key_received = rwtp_session_read(&alice, bob_ask_pub_keyf);
    rwtp_frame_destroy(bob_ask_pub_keyf);
    REQUIRE(alice_ask_pub_key_received.status_code == RWTP_ASKOPT);
    REQUIRE(alice_set_pub_key_received.opt == RWTP_OPTS_PUBKEY);
    rwtp_frame *alice_private_key, *alice_iv;
    alice_private_key = rwtp_frame_gen_private_key();
    alice_iv = alice.nonce_or_header;
    rwtp_frame *alice_set_pub_keyf = rwtp_session_send_set_pub_key(&alice, alice_private_key, alice_iv);
    rwtp_session_read_result bob_set_pub_key_received = rwtp_session_read(&bob, alice_set_pub_keyf);
    rwtp_frame_destroy(alice_set_pub_keyf);
    REQUIRE(bob_set_pub_key_received.status_code == RWTP_SETOPT);
    REQUIRE(bob_set_pub_key_received.opt == RWTP_OPTS_PUBKEY);

    /* Check crypto info */
    REQUIRE(bob.self_private_key->iovec_len == crypto_box_SECRETKEYBYTES);
    REQUIRE(bob.remote_public_key->iovec_len == crypto_box_PUBLICKEYBYTES);
    REQUIRE(alice.self_private_key->iovec_len == crypto_box_SECRETKEYBYTES);
    REQUIRE(alice.remote_public_key->iovec_len == crypto_box_PUBLICKEYBYTES);
    REQUIRE(bob.nonce_or_header->iovec_len == crypto_box_NONCEBYTES);
    REQUIRE(alice.nonce_or_header->iovec_len == crypto_box_NONCEBYTES);
    unsigned char alice_public_key[crypto_box_PUBLICKEYBYTES];
    crypto_scalarmult_base(alice_public_key, alice.self_private_key->iovec_data);
    unsigned char bob_public_key[crypto_box_PUBLICKEYBYTES];
    crypto_scalarmult_base(bob_public_key, bob.self_private_key->iovec_data);
    REQUIRE_BUF_EQ(alice.remote_public_key->iovec_data, bob_public_key, crypto_box_PUBLICKEYBYTES);
    REQUIRE_BUF_EQ(bob.remote_public_key->iovec_data, alice_public_key, crypto_box_PUBLICKEYBYTES);
    REQUIRE_BUF_EQ(alice.nonce_or_header->iovec_data, bob.nonce_or_header->iovec_data, crypto_box_NONCEBYTES);

    rwtp_frame *bob_set_timef = rwtp_session_send_set_time(&bob, time(NULL)-1);
    /* In real world, the time should be as is. But I need to check if the 'time_offest' works. Though, well, rwtp doesn't care about that field. (Rubicon 29/Jul./2021) */
    rwtp_frame *bob_ask_timef = rwtp_session_send_ask_option(&bob, RWTP_OPTS_TIME);
    rwtp_session_read_result alice_set_time_received = rwtp_session_read(&alice, bob_set_timef);
    rwtp_frame_destroy(bob_set_timef);
    REQUIRE(alice_set_time_received.status_code == RWTP_SETOPT);
    REQUIRE(alice_set_time_received.opt == RWTP_OPTS_TIME);
    REQUIRE(alice.time_offest == 1 || alice.time_offest == 2);
    rwtp_session_read_result alice_ask_time_received = rwtp_session_read(&alice, bob_ask_timef);
    rwtp_frame_destroy(bob_ask_timef);
    REQUIRE(alice_ask_time_received.status_code == RWTP_ASKOPT);
    REQUIRE(alice_ask_time_received.opt == RWTP_OPTS_TIME);
    rwtp_frame *alice_set_timef = rwtp_session_send_set_time(&alice, time(NULL));
    rwtp_session_read_result bob_set_time_received = rwtp_session_read(&bob, alice_set_timef);
    rwtp_frame_destroy(alice_set_timef);
    REQUIRE(bob_set_time_received.status_code == RWTP_SETOPT);
    REQUIRE(bob_set_time_received.opt == RWTP_OPTS_TIME);
    rwtp_session_deinit(&alice);
    rwtp_session_deinit(&bob);
}
