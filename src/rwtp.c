#include <rwtp.h>

#include <msgpack.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include <asprintf.h>

/* A wrapper around strtoll and strtol, automatically choose correct one for int64_t. */
static int64_t strtoint64 (const char *restrict str, char **restrict str_end, int base){
    static const int int64_nbytes = sizeof(int64_t);
    assert(int64_nbytes == sizeof(long long) || int64_nbytes == sizeof(long));

    if (int64_nbytes == sizeof (long long)){
        return strtoll(str, str_end, base);
    } else {
        return strtol(str, str_end, base);
    }
}

/* Convert n into cstring. Caller owns the return value. */
static char *int64tostr(int64_t n){
    // TODO: a new version without the use of asprintf
    char *str;
    asprintf(&str, "%jd", n);
    return str;
}

/* Return true if str of length is null-terminated byte string, false otherwise */
static bool check_cstring(const char str[], size_t length){
    return str[length-1] == '\0';
}

int rwtp_init() {
    int sodium_ret = sodium_init();
    if (!sodium_ret) {
        return -1;
    }
    return 0;
}

int rwtp_frame_init(rwtp_frame *self, size_t iovec_len,
                    rwtp_frame *frame_next) {
    rwtp_frame_reset(self);
    if (iovec_len > 0) {
        self->iovec_len = iovec_len;
        self->iovec_data = malloc(iovec_len);
        if (!self->iovec_data) {
            rwtp_frame_reset(self);
            return -1;
        }
    }
    self->frame_next = frame_next;
    return 0;
}

void rwtp_frame_deinit(rwtp_frame *self) {
    free(self->iovec_data);
    rwtp_frame_reset(self);
}

void rwtp_frame_deinit_all(rwtp_frame *self) {
    rwtp_frame *next = self;
    while ((self = next)) {
        next = self->frame_next;
        rwtp_frame_deinit(self);
    }
}

rwtp_frame *rwtp_frame_new(size_t iovec_len, rwtp_frame *frame_next) {
    rwtp_frame *new_frame = malloc(sizeof(rwtp_frame));
    if (!new_frame) {
        return NULL;
    }
    if (rwtp_frame_init(new_frame, iovec_len, frame_next)) {
        free(new_frame);
        return NULL;
    }
    return new_frame;
}

void rwtp_frame_destroy(rwtp_frame *self) {
    rwtp_frame_deinit(self);
    free(self);
}

void rwtp_frame_destroy_all(rwtp_frame *self) {
    rwtp_frame_deinit_all(self);
    rwtp_frame *next = self;
    while ((self = next)) {
        next = self->frame_next;
        free(self);
    }
}

void rwtp_frame_reset(rwtp_frame *self) {
    *self = (struct rwtp_frame){
        .iovec_len = 0,
        .iovec_data = NULL,
        .frame_next = NULL,
    };
}

rwtp_frame *rwtp_frame_pack_frames(const rwtp_frame *self) {
    msgpack_sbuffer sbuf;
    msgpack_packer packer;
    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&packer, &sbuf, msgpack_sbuffer_write);

    {
        const rwtp_frame *current = self;
        do {
            msgpack_pack_bin(&packer, current->iovec_len);
            msgpack_pack_bin_body(&packer, current->iovec_data, current->iovec_len);
        } while ((current = self->frame_next));
    }

    rwtp_frame *result = rwtp_frame_new(sbuf.size, NULL);
    memcpy(result->iovec_data, sbuf.data, sbuf.size);
    msgpack_sbuffer_release(&sbuf);
    return result;
}

rwtp_frame *rwtp_frame_unpack_frames(const rwtp_frame *self) {
    rwtp_frame *result_head, *result_current, *result_last;
    msgpack_unpacker unpacker;
    if (!msgpack_unpacker_init(&unpacker, 128)) {
        return NULL;
    }
    if (msgpack_unpacker_buffer_capacity(&unpacker) < self->iovec_len) {
        if (!msgpack_unpacker_reserve_buffer(&unpacker, self->iovec_len)) {
            msgpack_unpacker_destroy(&unpacker);
            return NULL;
        }
    }
    memcpy(msgpack_unpacker_buffer(&unpacker), self->iovec_data,
           self->iovec_len);
    msgpack_unpacker_buffer_consumed(&unpacker, self->iovec_len);

    while (true) {
        msgpack_unpacked unpacked;
        msgpack_unpack_return unpacking_result;
        msgpack_unpacked_init(&unpacked);
        unpacking_result = msgpack_unpacker_next(&unpacker, &unpacked);

        if (unpacking_result == MSGPACK_UNPACK_SUCCESS) {
            if (unpacked.data.type != MSGPACK_OBJECT_BIN) {
                msgpack_unpacker_destroy(&unpacker);
                return NULL;
            }
            msgpack_object_bin binary = unpacked.data.via.bin;
            result_last = result_current;
            result_current = rwtp_frame_new(binary.size, NULL);
            memcpy(result_current->iovec_data, binary.ptr, binary.size);
            if (!result_head) {
                result_head = result_current;
            }
            if (result_last) {
                result_last->frame_next = result_current;
            }
        } else if (unpacking_result == MSGPACK_UNPACK_CONTINUE) {
            msgpack_unpacked_destroy(&unpacked);
            break;
        } else if (unpacking_result == MSGPACK_UNPACK_PARSE_ERROR) {
            msgpack_unpacked_destroy(&unpacked);
            msgpack_unpacker_destroy(&unpacker);
            return NULL;
        } else {
            puts("rwtp_frame_unpack_frames: msgpack_unpacker_next return "
                 "unexpected code.");
            exit(EXIT_FAILURE);
        }
    }

    msgpack_unpacker_destroy(&unpacker);

    return result_head;
}

rwtp_frame *rwtp_frame_last_of(rwtp_frame *self) {
    return self->frame_next ? rwtp_frame_last_of(self->frame_next) : self;
}

rwtp_frame *rwtp_frame_encrypt_single(const rwtp_frame *self,
                                      const rwtp_crypto_save *save) {
    rwtp_frame *result =
        rwtp_frame_new(crypto_box_MACBYTES + self->iovec_len, NULL);
    if (!result) {
        return NULL;
    }
    if (crypto_box_easy(result->iovec_data, self->iovec_data, self->iovec_len,
                        save->nonce->iovec_data, save->pk->iovec_data,
                        save->sk->iovec_data)) {
        rwtp_frame_destroy(result);
        return NULL;
    }
    return result;
}

rwtp_frame *rwtp_frame_decrypt_single(const rwtp_frame *self,
                                      const rwtp_crypto_save *save) {
    rwtp_frame *result =
        rwtp_frame_new(self->iovec_len - crypto_box_MACBYTES, NULL);
    if (!result) {
        return NULL;
    }
    if (crypto_box_open_easy(result->iovec_data, self->iovec_data,
                             self->iovec_len, save->nonce->iovec_data, save->pk->iovec_data,
                             save->sk->iovec_data)) {
        rwtp_frame_destroy(result);
        return NULL;
    }
    return result;
}

rwtp_frame *rwtp_frames_chain(rwtp_frame frames[], size_t frames_n) {
    for (; frames_n >= 2; frames_n--) {
        frames[frames_n - 2].frame_next = &(frames[frames_n - 1]);
    }
    return frames;
}

static rwtp_frame *rwtp_session_pkm_encrypt_single(const rwtp_session *self,
                                                   const rwtp_frame *f) {
    rwtp_crypto_save csave = {
        .pk = self->remote_public_key->iovec_data,
        .sk = self->self_private_key->iovec_data,
        .nonce = self->nonce_or_header->iovec_data,
    };
    rwtp_frame *result = rwtp_frame_encrypt_single(f, &csave);
    sodium_increment(self->nonce_or_header->iovec_data,
                     self->nonce_or_header->iovec_len);
    return result;
}

static rwtp_frame *rwtp_session_skm_encrypt_single(const rwtp_session *self,
                                                   const rwtp_frame *f) {
    rwtp_frame *result = rwtp_frame_new(
        f->iovec_len + crypto_secretstream_xchacha20poly1305_ABYTES, NULL);
    if (!result) {
        return NULL;
    }
    if (crypto_secretstream_xchacha20poly1305_push(
            self->_state, result->iovec_data, NULL, f->iovec_data, f->iovec_len,
            NULL, 0, 0)) {
        rwtp_frame_destroy(result);
        return NULL;
    }
    return result;
}

/* Encrypt single rwtp_frame. Caller own return value. */
static rwtp_frame *rwtp_session_encrypt_single(const rwtp_session *self,
                                               const rwtp_frame *f) {
    if (self->remote_public_key) {
        return rwtp_session_pkm_encrypt_single(self, f);
    } else if (self->secret_key) {
        return rwtp_session_skm_encrypt_single(self, f);
    } else {
        // in neither public-key mode nor secret-key mode, use seal boxes
        rwtp_crypto_save csave = {.sk = self->network_key};
        return rwtp_frame_encrypt_single_seal(f, &csave);
    }
}

/* Decrypt single rwtp_frame. Caller own return value. */
static rwtp_frame *rwtp_session_decrypt_single(rwtp_session *self,
                                               const rwtp_frame *f) {
    if (self->remote_public_key) {
        unsigned char msg_nonce[crypto_box_NONCEBYTES];
        rwtp_frame msg_nonce_frame = {.iovec_data = msg_nonce,
                                      .iovec_len = crypto_box_NONCEBYTES};
        rwtp_crypto_save csave = {
            .pk = self->remote_public_key->iovec_data,
            .sk = self->self_private_key->iovec_data,
            .nonce = &msg_nonce_frame,
        };
        rwtp_frame *result = rwtp_frame_decrypt_single(f, &csave);
        return result;
    } else if (self->secret_key) {
        rwtp_frame *result = rwtp_frame_new(
            f->iovec_len - crypto_secretstream_xchacha20poly1305_ABYTES, NULL);
        if (crypto_secretstream_xchacha20poly1305_pull(
                self->_state, result->iovec_data, NULL, NULL, f->iovec_data,
                f->iovec_len, NULL, 0)) {
            rwtp_frame_destroy(result);
            return NULL;
        }
        return result;
    } else {
        rwtp_crypto_save csave = {.sk = self->network_key};
        rwtp_frame *result = rwtp_frame_decrypt_single_seal(f, &csave);
        return result;
    }
}

rwtp_session_read_result rwtp_session_read(rwtp_session *self, const rwtp_frame *raw_single){
    rwtp_frame *plaintext_blk = rwtp_session_decrypt_single(self, raw_single);
    if (!plaintext_blk){
        return (struct rwtp_session_read_result){-1};
    }
    rwtp_frame *frames = rwtp_frame_unpack_frames(plaintext_blk);
    rwtp_frame_destroy(plaintext_blk);
    if (frames->iovec_len != sizeof(uint8_t)){
        return (struct rwtp_session_read_result){-1};
    }
    uint8_t ctl_code = *((uint8_t*) frames->iovec_data);
    if (ctl_code == RWTP_DATA){
        rwtp_frame *user_frame_head = frames->frame_next;
        rwtp_frame_destroy(frames);
        if (!user_frame_head){
            return (struct rwtp_session_read_result){-1};
        }
        return (struct rwtp_session_read_result){RWTP_DATA, user_frame_head};
    } else if (ctl_code == RWTP_SETOPT){
        rwtp_frame *opt_key_frame = frames->frame_next;
        if (!rwtp_frame_check_size_fixed(opt_key_frame, sizeof(uint8_t))){
            return (struct rwtp_session_read_result){-1};
        }
        uint8_t opt_key = *((uint8_t*) opt_key_frame->iovec_data);
        if (opt_key == RWTP_OPTS_PUBKEY && !self->secret_key){
            rwtp_frame *pub_keyf, *ivf;
            if (!(pub_keyf=opt_key_frame->frame_next) || !(ivf=pub_keyf->frame_next)){
                rwtp_frame_destroy_all(frames);
                return (struct rwtp_session_read_result){-1};
            } else if (pub_keyf->iovec_len != crypto_box_PUBLICKEYBYTES || ivf->iovec_len != crypto_box_NONCEBYTES){
                rwtp_frame_destroy_all(frames);
                return (struct rwtp_session_read_result){-1};
            }
            pub_keyf = rwtp_frame_clone(pub_keyf);
            ivf = rwtp_frame_clone(ivf);
            pub_keyf->frame_next = ivf->frame_next = NULL;
            self->remote_public_key = pub_keyf;
            self->nonce_or_header = ivf;
        } else if (opt_key == RWTP_OPTS_SECKEY && !self->remote_public_key) {
            rwtp_frame *sec_keyf, *headerf;
            if (!(sec_keyf=opt_key_frame->frame_next) || !(headerf = sec_keyf->frame_next)){
                rwtp_frame_destroy_all(frames);
                return (struct rwtp_session_read_result){-1};
            } else if (sec_keyf->iovec_len != crypto_secretstream_xchacha20poly1305_KEYBYTES || headerf->iovec_len != crypto_secretstream_xchacha20poly1305_HEADERBYTES){
                rwtp_frame_destroy_all(frames);
                return (struct rwtp_session_read_result){-1};
            }
            sec_keyf = rwtp_frame_clone(sec_keyf);
            headerf = rwtp_frame_clone(headerf);
            sec_keyf->frame_next = headerf->frame_next = NULL;
            self->secret_key = sec_keyf;
            self->nonce_or_header = headerf;
        } else if (opt_key == RWTP_OPTS_TIME) {
            rwtp_frame *timef;
            if (!(timef = opt_key_frame->frame_next)){
                rwtp_frame_destroy_all(frames);
                return (struct rwtp_session_read_result){-1};
            }
            intmax_t local_time = time(NULL);
            if (!check_cstring(timef->iovec_data, timef->iovec_len)){
                rwtp_frame_destroy_all(frames);
                return (struct rwtp_session_read_result){-1};
            }
            int64_t remote_time = strtoint64(timef->iovec_data, NULL, 0);
            if (errno == ERANGE){
                rwtp_frame_destroy_all(frames);
                return (struct rwtp_session_read_result){-1};
            }
            int64_t offest = remote_time - local_time;
            self->time_offest = offest;
        } else {
            rwtp_frame_destroy_all(frames);
            return (struct rwtp_session_read_result){-1};
        }
        rwtp_frame_destroy_all(frames);
        return (struct rwtp_session_read_result){RWTP_SETOPT, .opt=opt_key};
    } else if (ctl_code == RWTP_ASKOPT){
        rwtp_frame *opt_keyf = frames->frame_next;
        if (rwtp_frame_check_size_fixed(opt_keyf, sizeof(uint8_t))){
            uint8_t opt_key = *((uint8_t*) opt_keyf->iovec_data);
            if (opt_key < RWTP_OPTS_PUBKEY && opt_key > RWTP_OPTS_PUBKEY){
                rwtp_frame_destroy_all(frames);
                return (struct rwtp_session_read_result){-1};
            }
            return (struct rwtp_session_read_result){RWTP_ASKOPT, .opt=opt_key};
        } else {
            rwtp_frame_destroy_all(frames);
            return (struct rwtp_session_read_result){-1};
        }
    } else {
        rwtp_frame_destroy_all(frames);
        return (struct rwtp_session_read_result){-1};
    }
}

rwtp_frame *rwtp_session_send(rwtp_session *self, rwtp_frame *raw){
    rwtp_frame head = {
        .iovec_data = (uint8_t*)&RWTP_DATA,
        .iovec_len = sizeof(uint8_t),
        .frame_next = raw,
    };
    rwtp_frame *blk = rwtp_frame_pack_frames(&head);
    if (!blk){
        return NULL;
    }
    rwtp_frame *result = rwtp_session_encrypt_single(self, blk);
    rwtp_frame_destroy(blk);
    return result;
}

rwtp_frame *rwtp_session_send_set_sec_key(rwtp_session *self, const rwtp_frame *secret_key){
    assert(self->network_key);
    assert(!rwtp_session_check_public_key_mode(self)); // Should not in public-key mode
    assert(self->secret_key->iovec_len == crypto_secretstream_xchacha20poly1305_KEYBYTES);

    rwtp_frame *dup_secret_key = rwtp_frame_clone((rwtp_frame*)secret_key);

    self->nonce_or_header = rwtp_frame_new(crypto_secretstream_xchacha20poly1305_HEADERBYTES, NULL);
    if (!self->nonce_or_header){
        return NULL;
    }
    if (!self->_state){
        self->_state = malloc(sizeof(crypto_secretstream_xchacha20poly1305_state));
        if (!self->_state){
            rwtp_frame_destroy(self->nonce_or_header);
            return NULL;
        }
    }
    if(crypto_secretstream_xchacha20poly1305_init_push(self->_state, self->nonce_or_header->iovec_data, secret_key->iovec_data)){
        rwtp_frame_destroy(self->nonce_or_header);
        free(self->_state);
        return NULL;
    }

    rwtp_frame message[4] = {
        {(uint8_t*)&RWTP_SETOPT, sizeof(uint8_t)},
        {(uint8_t*)&RWTP_OPTS_SECKEY, sizeof(uint8_t)},
        *dup_secret_key,
        *(self->nonce_or_header),
    };
    rwtp_frames_chain(message, 4);
    rwtp_frame *blk = rwtp_frame_pack_frames(message);
    rwtp_frame *result = rwtp_session_encrypt_single(self, blk);
    rwtp_frame_destroy(blk);

    self->secret_key = dup_secret_key;
    return result;
}

rwtp_frame *rwtp_session_send_set_pub_key(rwtp_session *self,
                                          const rwtp_frame *self_private_key,
                                          const rwtp_frame *iv) {
    assert(self->network_key);
    assert(!rwtp_session_check_secret_key_mode(self)); // Should not in secret-key mode
    assert(self_private_key->iovec_len == crypto_box_SECRETKEYBYTES);
    assert(iv->iovec_len == crypto_box_NONCEBYTES);

    unsigned char pk[crypto_box_PUBLICKEYBYTES];
    crypto_scalarmult_base(pk, self_private_key->iovec_data);
    rwtp_frame pk_frame = {
        .iovec_data = pk,
        .iovec_len = crypto_box_PUBLICKEYBYTES,
    };
    rwtp_frame message[4] = {{(uint8_t*)&RWTP_SETOPT, sizeof(uint8_t)},{(uint8_t*)&RWTP_OPTS_PUBKEY, sizeof(uint8_t)}, pk_frame, *iv};
    rwtp_frames_chain(message, 4);
    rwtp_frame *blk = rwtp_frame_pack_frames(message);
    rwtp_frame *result;
    result = rwtp_session_encrypt_single(self, blk);
    rwtp_frame_destroy(blk);
    if (!result) {
        return NULL;
    }

    // After message "sent", we update options
    self->self_private_key = rwtp_frame_clone(self_private_key);
    self->nonce_or_header = rwtp_frame_clone(iv);

    return result;
}

rwtp_frame *rwtp_session_send_set_time(const rwtp_session *self, int64_t time){
    assert(self->remote_public_key || self->secret_key);
    char *timestr = int64tostr(time);
    rwtp_frame timef = {
        .iovec_data = timestr,
        .iovec_len = sizeof(uint64_t),
    };
    rwtp_frame message[3] = {
        {(uint8_t*)&RWTP_SETOPT, sizeof(uint8_t)},
        {(uint8_t*)&RWTP_OPTS_TIME, sizeof(uint8_t)},
        timef,
    };
    rwtp_frames_chain(message, 3);
    rwtp_frame *blk = rwtp_frame_pack_frames(message);
    free(timestr);
    if (!blk){
        return NULL;
    }
    rwtp_frame *result = rwtp_session_encrypt_single(self, blk);
    rwtp_frame_destroy(blk);
    return result;
}

rwtp_frame *rwtp_frame_encrypt_single_seal(const rwtp_frame *self,
                                           const rwtp_crypto_save *save) {
    rwtp_frame *result =
        rwtp_frame_new(crypto_box_SEALBYTES + self->iovec_len, NULL);
    if (result) {
        unsigned char pk[crypto_box_PUBLICKEYBYTES];
        if (!save->pk) {
            crypto_scalarmult_base(pk, save->pk->iovec_data);
        }
        if (crypto_box_seal(result->iovec_data, self->iovec_data,
                            self->iovec_len,
                            save->pk ? save->pk->iovec_data : pk)) {
            rwtp_frame_destroy(result);
            return NULL;
        }
        return result;
    }
    return NULL;
}

rwtp_frame *rwtp_frame_decrypt_single_seal(const rwtp_frame *self,
                                           const rwtp_crypto_save *save) {
    rwtp_frame *result =
        rwtp_frame_new(self->iovec_len - crypto_box_SEALBYTES, NULL);
    if (result) {
        unsigned char pk[crypto_box_PUBLICKEYBYTES];
        crypto_scalarmult_base(pk, save->sk->iovec_data);
        if (crypto_box_seal_open(result->iovec_data, self->iovec_data,
                                 self->iovec_len, pk, save->sk->iovec_data)) {
            rwtp_frame_destroy(result);
            return NULL;
        }
        return result;
    }
    return NULL;
}

rwtp_frame *rwtp_frame_clone(const rwtp_frame *self){
    rwtp_frame *copy = rwtp_frame_new(self->iovec_len, self->frame_next);
    memcpy(copy->iovec_data, self->iovec_data, self->iovec_len);
    return copy;
}

rwtp_frame *rwtp_frame_clone_all(rwtp_frame *self){
    if (self){
        rwtp_frame *copy = rwtp_frame_clone(self);
        copy->frame_next = rwtp_frame_clone_all(self->frame_next);
        return copy;
    } else {
        return NULL;
    }
}

bool rwtp_frame_check_size_fixed(rwtp_frame *self, size_t size){
    if (self){
        return self->iovec_len == size;
    } else {
        return false;
    }
}

void rwtp_session_deinit(rwtp_session *self){
    if (self->network_key){
        rwtp_frame_destroy(self->network_key);
    }
    if (self->nonce_or_header){
        rwtp_frame_destroy(self->nonce_or_header);
    }
    if (self->remote_public_key){
        rwtp_frame_destroy(self->remote_public_key);
    }
    if(self->secret_key){
        rwtp_frame_destroy(self->secret_key);
    }
    if(self->self_private_key){
        rwtp_frame_destroy(self->self_private_key);
    }
    if(self->_state){
        free(self->_state);
    }
}

bool rwtp_session_check_seal_mode(rwtp_session *self){
    return self->network_key && !(self->remote_public_key || self->secret_key);
}

bool rwtp_session_check_public_key_mode(rwtp_session *self){
    return !!self->remote_public_key;
}

bool rwtp_session_check_secret_key_mode(rwtp_session *self){
    return !!self->secret_key;
}

bool rwtp_session_check_complete_mode(rwtp_session *self){
    return rwtp_session_check_public_key_mode(self) || rwtp_session_check_secret_key_mode(self);
}

rwtp_frame *rwtp_frame_gen_private_key(){
    unsigned char privatek[crypto_box_SECRETKEYBYTES], pubk[crypto_box_PUBLICKEYBYTES];
    if(crypto_box_keypair(pubk, privatek)){
        return NULL;
    }
    rwtp_frame *result = rwtp_frame_new(crypto_box_SECRETKEYBYTES, NULL);
    if (!result) return NULL;
    memcpy(result->iovec_data, privatek, result->iovec_len);
    return result;
}

rwtp_frame *rwtp_frame_gen_network_key(){
    return rwtp_frame_gen_private_key();
}

rwtp_frame *rwtp_frame_gen_secret_key(){
    unsigned char sk[crypto_secretstream_xchacha20poly1305_KEYBYTES];
    crypto_secretstream_xchacha20poly1305_keygen(sk);
    rwtp_frame *result = rwtp_frame_new(crypto_secretstream_xchacha20poly1305_KEYBYTES, NULL);
    if (!result) return NULL;
    memcpy(result->iovec_data, sk, result->iovec_len);
    return result;
}

rwtp_frame *rwtp_frame_gen_public_key_mode_iv(){
    rwtp_frame *result = rwtp_frame_new(crypto_box_NONCEBYTES, NULL);
    if (!result){
        return NULL;
    }
    randombytes_buf(result->iovec_data, result->iovec_len);
    return result;
}
