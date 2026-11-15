#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"

/* Credential ids (48 bytes): ver (1) || credProtect (1) || nonce (30) || tag (16).
 * The tag is HMAC(master, "tag2" || rpIdHash || id[0..32))[0..16), so version and credProtect are
 * authenticated. Ids from the old format (32-byte nonce, "tag" label) fail the tag check: "not ours".
 * Keys are re-derived from the master and id[0..32) on every use. */
#define CRED_ID_VER 1
esp_err_t cred_new_id(const uint8_t rp_hash[32], uint8_t cred_protect, uint8_t cred_id[48]);
/* True when the id carries a valid tag for this rp_hash under the current master. */
bool cred_id_is_ours(const uint8_t rp_hash[32], const uint8_t *cred_id, size_t len);
/* credProtect level (1..3) of an id that cred_id_is_ours() accepted. */
static inline uint8_t cred_id_protect(const uint8_t cred_id[48]) { return cred_id[1]; }
/* Uncompressed P-256 public key (65 bytes) for the credential. */
esp_err_t cred_public_key(const uint8_t rp_hash[32], const uint8_t cred_id[48], uint8_t pub[65]);
/* ECDSA-SHA256 over msg with the credential key; output is raw r||s (64 bytes). */
esp_err_t cred_sign(const uint8_t rp_hash[32], const uint8_t cred_id[48], const uint8_t *msg, size_t len,
                    uint8_t sig[64]);
/* U2F batch attestation (attest_batch.h): signature with the shared key and its certificate. */
esp_err_t attest_sign(const uint8_t *msg, size_t len, uint8_t sig[64]);
const uint8_t *attest_cert(size_t *der_len);
/* Converts raw r||s (64 bytes) to a DER ECDSA signature. der must hold at least 72 bytes. */
size_t cred_raw_to_der(const uint8_t raw[64], uint8_t der[72]);

/* SHA-256 via PSA. */
esp_err_t cred_sha256(const uint8_t *in, size_t len, uint8_t out[32]);
/* Constant-time compare; true when equal. */
bool cred_ct_equal(const uint8_t *a, const uint8_t *b, size_t n);

/* Random bytes for keys and secrets: HMAC-SHA256 over a pool seeded while a true entropy source was
 * on (cred_rng_seed), mixed with fresh esp_fill_random output on every call. */
void cred_rng_seed(void);
void cred_rng(uint8_t *out, size_t len);

/* ---- hmac-secret and PIN/UV auth protocols 1 and 2 ---- */
/* HMAC-SHA-256 with a 32-byte key. */
esp_err_t cred_hmac(const uint8_t key[32], const uint8_t *msg, size_t len, uint8_t out[32]);
/* AES-256-CBC without padding; len must be a non-zero multiple of 16. in and out must not overlap. */
esp_err_t cred_aes_cbc(bool encrypt, const uint8_t key[32], const uint8_t iv[16], const uint8_t *in, size_t len,
                       uint8_t *out);
/* CredRandom for hmac-secret: HMAC(master, label || rpIdHash || id[0..32)), with a separate label for
 * CredRandomWithUV (CTAP 2.1 §12.5: two secrets per credential). */
esp_err_t cred_hmac_secret(const uint8_t rp_hash[32], const uint8_t cred_id[48], bool uv, uint8_t out[32]);
/* Fresh key-agreement key pairs for protocols 1 and 2 (boot and reset). */
esp_err_t cred_ka_regen(void);
/* Uncompressed public key of the key-agreement key for proto (1 or 2). */
esp_err_t cred_ka_public(int proto, uint8_t pub[65]);
/* decapsulate(): ECDH with the peer point (uncompressed, checked on-curve by PSA), then the protocol kdf.
 * ss gets 32 bytes (v1) or 64 bytes (v2: HMAC key || AES key). ESP_ERR_INVALID_ARG for a bad peer point. */
esp_err_t cred_ka_shared(int proto, const uint8_t peer[65], uint8_t ss[64]);
