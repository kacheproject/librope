
#include <stdbool.h>
#include <sodium.h>

const uint8_t RWTP_DATA = 0;
const uint8_t RWTP_SETOPT = 1;
const uint8_t RWTP_ASKOPT = 2;

const uint8_t RWTP_OPTS_PUBKEY = 1;
const uint8_t RWTP_OPTS_SECKEY = 2;
const uint8_t RWTP_OPTS_TIME = 3;

/* Initialise dependencies required by rwtp. You should call it at least once before any use of this library. 
* Return -1 when failed.
*/
int rwtp_init();

/* Single-linked iovec structure.
* See rwtp_frame_init, rwtp_frame_new for constructing.
*/
typedef struct rwtp_frame {
    void *iovec_data;
    size_t iovec_len;
    struct rwtp_frame *frame_next;
} rwtp_frame;

/* Initialise rwtp_frame structure, which using malloc for data buffer. If iovec_len is 0, skip memory allocation. Return -1 if failed.
* Use rwtp_frame_deinit or rwtp_frame_deinit_all to deinitialise structures.
* Example:
*     rwtp_frame frame;
*     rwtp_frame_init(&frame, sizeof(uint8_t), NULL);
*     rwtp_frame_deinit(&frame);
*
* If you want a rwtp_frame with on-stack data buffer, construct by hand:
*     uint8_t number;
*     rwtp_frame frame = {&number, sizeof(uint8_t), NULL};
* 
* See rwtp_frame_new for on-heap structure.
*/
int rwtp_frame_init(rwtp_frame *self, size_t iovec_len, rwtp_frame *frame_next);
/* Deinitialise one rwtp_frame structure. See rwtp_frame_init.*/
void rwtp_frame_deinit(rwtp_frame *self);
/* Deinitialise all rwtp_frame structures on the chain. See rwtp_frame_init.*/
void rwtp_frame_deinit_all(rwtp_frame *self);

/* Create a rwtp_frame structure on heap and initialise the data buffer using malloc. Use rwtp_frame_init internally. Return NULL if failed.
* Use rwtp_frame_destroy or rwtp_frame_destroy_all to destroy such structures.
* Example:
*     rwtp_frame *frame = rwtp_frame_new(sizeof(uint8_t), NULL);
*     *(frame->iovec_data) = 0;
*     rwtp_frame_destroy(frame);
*
* See rwtp_frame_init for on-stack structure initialising.
*/
rwtp_frame *rwtp_frame_new(size_t iovec_len, rwtp_frame *frame_next);
/* Deinitialise and destroy one rwtp_frame structure. See rwtp_frame_new. */
void rwtp_frame_destroy(rwtp_frame *self);
/* Deinitialise and destroy all structures on the chain. See rwtp_frame_new. */
void rwtp_frame_destroy_all(rwtp_frame *self);

/* Reset the values in the structure. THIS IS NOT DECONSTRUCTING!
* See rwtp_frame_deinit, rwtp_frame_deinit_all, rwtp_frame_destroy, rwtp_frame_destroy_all.
*/
void rwtp_frame_reset(rwtp_frame *self);

rwtp_frame *rwtp_frame_pack_frames(const rwtp_frame *self);
rwtp_frame *rwtp_frame_unpack_frames(const rwtp_frame *self);

rwtp_frame *rwtp_frame_last_of(rwtp_frame *self);

rwtp_frame *rwtp_frames_chain(rwtp_frame frames[], size_t frames_n);

rwtp_frame *rwtp_frame_clone(const rwtp_frame *self);
rwtp_frame *rwtp_frame_clone_all(rwtp_frame *self);

/* Return false if self is NULL or self->iovec_len != size, and true otherwise. */
bool rwtp_frame_check_size_fixed(rwtp_frame *self, size_t size);

typedef struct rwtp_crypto_save {
    rwtp_frame *pk;
    rwtp_frame *sk;
    rwtp_frame *nonce;
} rwtp_crypto_save;

/* Encrypt single rwtp_frame. Return the encrypted version which created with rwtp_frame_new, but NULL when failed.
* The pk, sk, nonce should be setted up in save, as requirement for crypto_box_easy.
* 
* Sizes:
* pk: crypto_box_PUBLICKEYBYTES
* sk: crypto_box_SECRETKEYBYTES
* nonce: crypto_box_NONCEBYTES
*
* See crypto_box_easy(libsodium), rwtp_frame_decrypt_single.
*/
rwtp_frame *rwtp_frame_encrypt_single(const rwtp_frame *self, const rwtp_crypto_save *save);
/* Decrypt single rwtp_frame. Return de plain-text version which created with rwtp_frame_new, but NULL when failed.
* The pk, sk in save should be setted up, and the nonce should be an empty rwtp_frame with crypto_box_MACBYTES bytes size.
* 
* Sizes:
* pk: crypto_box_PUBLICKEYBYTES
* sk: crypto_box_SECRETKEYBYTES
* nonce: crypto_box_NONCEBYTES
*
* See crypto_box_open_easy(libsodium), rwtp_frame_encrypt_single.
*/
rwtp_frame *rwtp_frame_decrypt_single(const rwtp_frame *self, const rwtp_crypto_save *save);

rwtp_frame *rwtp_frame_encrypt_single_seal(const rwtp_frame *self, const rwtp_crypto_save *save);
rwtp_frame *rwtp_frame_decrypt_single_seal(const rwtp_frame *self, const rwtp_crypto_save *save);

/* P2P: (public-key mode, using crypto_box_* API, transport key being rotated frequently during communication)
* 1. Alice: rwtp_write_set_pub_key (the pub key and iv is encrypted with network key pair, sealed)
* 2. Alice: rwtp_write_ask_pub_key (sent in sealed)
* 3. Bob: rwtp_write_set_pub_key (sent in encrypted with network key pair, sealed)
* 4. Alice: rwtp_write_set_time (encrypted)
* 5. Bob: rwtp_write_set_time (encrypted)
* (key rotating could be done by rwtp_write_set_pub_key)
*
* Pub/Sub: (secret-key mode, using crypto_secretstream_* API, transport key being rotated when connecting status changed)
* When every Sub connected or disconnected:
* 1. Pub: rwtp_write_set_sec_key (the secret key and iv is encrypted with network key pair, sealed)
* 2. Pub: rwtp_write_set_time (encrypted, optional)
*/

/* Session for a RWTP Connection. 
* A RWTP Connection have three kinds of mode: seal, public-key or secret-key.
*
* Public-key mode encrypt plain text or decrypt secret text with calculated shared secret key from local private key and remote public key.
* This mode use Xsalsa20-Poly1305MAC with X25519, and fits interactive communications. Provides:
* - Secure tunnel even if network key have been leaked.
* - Message order detection (with correct nonce rotating)
* - Forward, backward & isolated security
* Non-null value of remote_public_key states public-key mode.
*
* Secret-key mode encrypt plaintext or decrypt secret text with a shared secret key set by one of members.
* This mode use XChacha20-Poly1305MAC-IETF, which used by crypto_secretstream_* API. Provides:
* - Possiblity to build secure tunnel without requirement of remote's public key.
* - Forward & backward security
* - Message order detection
* Non-null value of remote_secret_key states secret-key mode.
* 
* Seal mode works just like public-key mode, but using random private key each time encrypting with network key as public key.
* This mode will be activated before entering public-key or secret-key mode, to provide a secure way to exchanging infomation (only when the network key exchanged in secure).
* Forward & backward security could not be ensured in this mode, sending application messages is not recommended.
*
* RWTP (Rope Wire Transfer Protocol) is a role-less secure transfering protocol,
uses a pre-shared long-term key (named network key) to protect infomation during "handshake".
*/
typedef struct rwtp_session {
    rwtp_frame *network_key; /* private key for crypto_box_seal* */

    rwtp_frame *remote_public_key;
    rwtp_frame *self_private_key;
    rwtp_frame *secret_key; /* used in secret-key mode */

    rwtp_frame *nonce_or_header;
    int64_t time_offest; /* remote - local */

    crypto_secretstream_xchacha20poly1305_state *_state; /* used in secret-key mode */
} rwtp_session;

typedef struct rwtp_session_read_result {
    int status_code;
    rwtp_frame *user_message;
    uint8_t opt;
} rwtp_session_read_result;

/* Read raw_single message. Return a structure with infomation about user needed to do.
* Assume result is a rwtp_session_read_result. result->status_code will be non-negative when operation successed,
the number will be one of protocol control code: RWTP_DATA, RWTP_SETOPT, RWTP_ASKOPT.
* result->user_message will be the pointer to message frames when status_code is RWTP_DATA.
Caller own the value, they should apply rwtp_frame_destroy* on the frames when the pointer is non-null.
* result->opt will be the option key when status_code is RWTP_SETOPT or RWTP_ASKOPT: RWTP_OPTS_PUBKEY.
*/
rwtp_session_read_result rwtp_session_read(rwtp_session *self, const rwtp_frame *raw_single);

rwtp_frame *rwtp_session_send(rwtp_session *self, rwtp_frame *raw);

rwtp_frame *rwtp_session_send_set_pub_key(rwtp_session *self, const rwtp_frame *self_private_key, const rwtp_frame *iv);

rwtp_frame *rwtp_session_send_set_sec_key(rwtp_session *self, const rwtp_frame *secret_key);

rwtp_frame *rwtp_session_send_set_time(const rwtp_session *self, int64_t time);

rwtp_frame *rwtp_session_send_ask_option(rwtp_session *self, uint8_t opt);

void rwtp_session_deinit(rwtp_session *self);

/* Return true if session is in seal mode, false otherwise. */
bool rwtp_session_check_seal_mode(rwtp_session *self);

/* Return true if session is in public-key mode, false otherwise. */
bool rwtp_session_check_public_key_mode(rwtp_session *self);

/* Return true if session is in secret-key mode, false otherwise. */
bool rwtp_session_check_secret_key_mode(rwtp_session *self);

/* Return true if session is in fully functional(in public-key or secret-key mode), false otherwise. */
bool rwtp_session_check_complete_mode(rwtp_session *self);

rwtp_frame *rwtp_frame_gen_network_key();
rwtp_frame *rwtp_frame_gen_private_key();
rwtp_frame *rwtp_frame_gen_secret_key();
rwtp_frame *rwtp_frame_gen_public_key_mode_iv();
