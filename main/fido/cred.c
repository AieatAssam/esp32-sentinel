#include <stdbool.h>
#include <string.h>
#include "esp_log.h"
#include "esp_random.h"
#include "mbedtls/platform_util.h"
#include "psa/crypto.h"
#include "store.h"
#include "cred.h"
#include "attest_batch.h"

#define TAG_LEN 16
static const char *TAG = "cred";

/* Imports a P-256 private scalar; PSA rejects 0 and values >= n with INVALID_ARGUMENT. */
static psa_status_t import_p256(const uint8_t sk[32], psa_key_usage_t usage, psa_algorithm_t alg,
                                mbedtls_svc_key_id_t *kid)
{
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attr, 256);
    psa_set_key_algorithm(&attr, alg);
    psa_set_key_usage_flags(&attr, usage);
    *kid = MBEDTLS_SVC_KEY_ID_INIT;
    return psa_import_key(&attr, sk, 32, kid);
}

/* Derives a P-256 key pair from HMAC(master, label || msg || i), retrying i until the scalar is valid. */
static esp_err_t derive_key(const uint8_t *msg, size_t len, mbedtls_svc_key_id_t *kid)
{
    if (len + 1 > 256) return ESP_ERR_INVALID_ARG;
    uint8_t buf[257];
    memcpy(buf, msg, len);
    for (unsigned i = 0; i < 256; i++) {
        buf[len] = (uint8_t)i;
        uint8_t sk[32];
        if (store_kdf(buf, len + 1, sk) != ESP_OK) return ESP_FAIL;
        psa_status_t st = import_p256(sk, PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_EXPORT,
                                      PSA_ALG_ECDSA(PSA_ALG_SHA_256), kid);
        mbedtls_platform_zeroize(sk, sizeof(sk));
        if (st == PSA_SUCCESS) return ESP_OK;          /* scalar in range */
        if (st != PSA_ERROR_INVALID_ARGUMENT) return ESP_FAIL;
    }
    return ESP_FAIL;
}

bool cred_ct_equal(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < n; i++) diff |= a[i] ^ b[i];
    return diff == 0;
}

/* tag = HMAC(master, "tag2" || rp_hash || id[0..32)). */
static esp_err_t id_tag(const uint8_t rp_hash[32], const uint8_t *head32, uint8_t tag[32])
{
    uint8_t msg[4 + 32 + 32];
    memcpy(msg, "tag2", 4);
    memcpy(msg + 4, rp_hash, 32);
    memcpy(msg + 36, head32, 32);
    return store_kdf(msg, sizeof(msg), tag);
}

esp_err_t cred_new_id(const uint8_t rp_hash[32], uint8_t cred_protect, uint8_t cred_id[48])
{
    if (cred_protect < 1 || cred_protect > 3) return ESP_ERR_INVALID_ARG;
    cred_id[0] = CRED_ID_VER;
    cred_id[1] = cred_protect;
    esp_fill_random(cred_id + 2, 30);   /* public nonce: needs uniqueness, not secrecy */
    uint8_t tag[32];
    if (id_tag(rp_hash, cred_id, tag) != ESP_OK) return ESP_FAIL;
    memcpy(cred_id + 32, tag, TAG_LEN);
    return ESP_OK;
}

bool cred_id_is_ours(const uint8_t rp_hash[32], const uint8_t *cred_id, size_t len)
{
    if (len != 48) return false;
    uint8_t tag[32];
    if (id_tag(rp_hash, cred_id, tag) != ESP_OK) return false;
    return cred_ct_equal(tag, cred_id + 32, TAG_LEN) && cred_id[0] == CRED_ID_VER && cred_id[1] >= 1 &&
           cred_id[1] <= 3;
}

static esp_err_t cred_key(const uint8_t rp_hash[32], const uint8_t cred_id[48], mbedtls_svc_key_id_t *kid)
{
    uint8_t msg[3 + 32 + 32];
    memcpy(msg, "key", 3);
    memcpy(msg + 3, rp_hash, 32);
    memcpy(msg + 35, cred_id, 32);
    return derive_key(msg, sizeof(msg), kid);
}

esp_err_t cred_public_key(const uint8_t rp_hash[32], const uint8_t cred_id[48], uint8_t pub[65])
{
    mbedtls_svc_key_id_t kid = MBEDTLS_SVC_KEY_ID_INIT;
    esp_err_t err = cred_key(rp_hash, cred_id, &kid);
    if (err != ESP_OK) return err;
    size_t olen = 0;
    psa_status_t st = psa_export_public_key(kid, pub, 65, &olen);
    psa_destroy_key(kid);
    return (st == PSA_SUCCESS && olen == 65) ? ESP_OK : ESP_FAIL;
}

static esp_err_t sign_with(mbedtls_svc_key_id_t kid, const uint8_t *msg, size_t len, uint8_t sig[64])
{
    size_t olen = 0;
    psa_status_t st = psa_sign_message(kid, PSA_ALG_ECDSA(PSA_ALG_SHA_256), msg, len, sig, 64, &olen);
    psa_destroy_key(kid);
    return (st == PSA_SUCCESS && olen == 64) ? ESP_OK : ESP_FAIL;
}

esp_err_t cred_sign(const uint8_t rp_hash[32], const uint8_t cred_id[48], const uint8_t *msg, size_t len,
                    uint8_t sig[64])
{
    mbedtls_svc_key_id_t kid = MBEDTLS_SVC_KEY_ID_INIT;
    esp_err_t err = cred_key(rp_hash, cred_id, &kid);
    if (err != ESP_OK) return err;
    return sign_with(kid, msg, len, sig);
}

esp_err_t attest_sign(const uint8_t *msg, size_t len, uint8_t sig[64])
{
    mbedtls_svc_key_id_t kid = MBEDTLS_SVC_KEY_ID_INIT;
    if (import_p256(k_batch_sk, PSA_KEY_USAGE_SIGN_MESSAGE, PSA_ALG_ECDSA(PSA_ALG_SHA_256), &kid) != PSA_SUCCESS) {
        return ESP_FAIL;
    }
    return sign_with(kid, msg, len, sig);
}

const uint8_t *attest_cert(size_t *der_len)
{
    *der_len = sizeof(k_batch_cert);
    return k_batch_cert;
}

/* ---- RNG pool ---- */
static uint8_t s_pool[32];
static uint32_t s_pool_ctr;

void cred_rng_seed(void)
{
    uint8_t e[64];
    esp_fill_random(e, sizeof(e));
    cred_sha256(e, sizeof(e), s_pool);
    mbedtls_platform_zeroize(e, sizeof(e));
}

void cred_rng(uint8_t *out, size_t len)
{
    while (len) {
        /* block = HMAC(pool, "out" || ctr || fresh), pool = HMAC(pool, "upd" || ctr || fresh) */
        uint8_t msg[3 + 4 + 32], blk[32];
        memcpy(msg + 3, &s_pool_ctr, 4);
        s_pool_ctr++;
        esp_fill_random(msg + 7, 32);
        memcpy(msg, "out", 3);
        if (cred_hmac(s_pool, msg, sizeof(msg), blk) != ESP_OK) esp_fill_random(blk, sizeof(blk));
        memcpy(msg, "upd", 3);
        cred_hmac(s_pool, msg, sizeof(msg), s_pool);
        size_t n = len < 32 ? len : 32;
        memcpy(out, blk, n);
        out += n;
        len -= n;
        mbedtls_platform_zeroize(blk, sizeof(blk));
        mbedtls_platform_zeroize(msg, sizeof(msg));
    }
}

/* DER INTEGER for a 32-byte unsigned value: strip leading zeros, add 0x00 when the high bit is set. */
static size_t der_int(const uint8_t *v, uint8_t *out)
{
    size_t i = 0;
    while (i < 31 && v[i] == 0) i++;
    size_t n = 32 - i;
    size_t o = 0;
    out[o++] = 0x02;
    if (v[i] & 0x80) {
        out[o++] = (uint8_t)(n + 1);
        out[o++] = 0x00;
    } else {
        out[o++] = (uint8_t)n;
    }
    memcpy(out + o, v + i, n);
    return o + n;
}

size_t cred_raw_to_der(const uint8_t raw[64], uint8_t der[72])
{
    uint8_t body[70];
    size_t n = der_int(raw, body);
    n += der_int(raw + 32, body + n);
    der[0] = 0x30;
    der[1] = (uint8_t)n;
    memcpy(der + 2, body, n);
    return n + 2;
}

esp_err_t cred_sha256(const uint8_t *in, size_t len, uint8_t out[32])
{
    size_t olen = 0;
    psa_status_t st = psa_hash_compute(PSA_ALG_SHA_256, in, len, out, 32, &olen);
    return (st == PSA_SUCCESS && olen == 32) ? ESP_OK : ESP_FAIL;
}

/* ---- hmac-secret / PIN/UV auth protocol crypto ---- */

esp_err_t cred_hmac(const uint8_t key[32], const uint8_t *msg, size_t len, uint8_t out[32])
{
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attr, PSA_KEY_TYPE_HMAC);
    psa_set_key_bits(&attr, 256);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&attr, PSA_ALG_HMAC(PSA_ALG_SHA_256));
    mbedtls_svc_key_id_t kid = MBEDTLS_SVC_KEY_ID_INIT;
    psa_status_t st = psa_import_key(&attr, key, 32, &kid);
    if (st != PSA_SUCCESS) {
        ESP_LOGE(TAG, "hmac import: %d", (int)st);
        return ESP_FAIL;
    }
    size_t olen = 0;
    st = psa_mac_compute(kid, PSA_ALG_HMAC(PSA_ALG_SHA_256), msg, len, out, 32, &olen);
    psa_destroy_key(kid);
    if (st != PSA_SUCCESS) ESP_LOGE(TAG, "hmac: %d", (int)st);
    return (st == PSA_SUCCESS && olen == 32) ? ESP_OK : ESP_FAIL;
}

esp_err_t cred_aes_cbc(bool encrypt, const uint8_t key[32], const uint8_t iv[16], const uint8_t *in, size_t len,
                       uint8_t *out)
{
    if (len == 0 || len % 16 != 0) return ESP_ERR_INVALID_SIZE;
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attr, 256);
    psa_set_key_usage_flags(&attr, encrypt ? PSA_KEY_USAGE_ENCRYPT : PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attr, PSA_ALG_CBC_NO_PADDING);
    mbedtls_svc_key_id_t kid = MBEDTLS_SVC_KEY_ID_INIT;
    psa_status_t st = psa_import_key(&attr, key, 32, &kid);
    if (st != PSA_SUCCESS) {
        ESP_LOGE(TAG, "aes import: %d", (int)st);
        return ESP_FAIL;
    }
    /* Multipart so the IV is ours (protocol 1 uses an all-zero IV; the one-shot API picks a random one). */
    psa_cipher_operation_t op = PSA_CIPHER_OPERATION_INIT;
    size_t a = 0, b = 0;
    st = encrypt ? psa_cipher_encrypt_setup(&op, kid, PSA_ALG_CBC_NO_PADDING)
                 : psa_cipher_decrypt_setup(&op, kid, PSA_ALG_CBC_NO_PADDING);
    if (st == PSA_SUCCESS) st = psa_cipher_set_iv(&op, iv, 16);
    if (st == PSA_SUCCESS) st = psa_cipher_update(&op, in, len, out, len, &a);
    if (st == PSA_SUCCESS) st = psa_cipher_finish(&op, out + a, len - a, &b);
    if (st != PSA_SUCCESS) {
        ESP_LOGE(TAG, "aes-cbc: %d", (int)st);
        psa_cipher_abort(&op);
    }
    psa_destroy_key(kid);
    return (st == PSA_SUCCESS && a + b == len) ? ESP_OK : ESP_FAIL;
}

/* CredRandomWithoutUV and CredRandomWithUV per credential, re-derived on use, so they need no storage and
 * work for resident and non-resident credentials alike. Derived for every credential, also those made
 * without the extension (the spec's SHOULD). */
esp_err_t cred_hmac_secret(const uint8_t rp_hash[32], const uint8_t cred_id[48], bool uv, uint8_t out[32])
{
    uint8_t msg[6 + 32 + 32];
    size_t l = uv ? 6 : 4;
    memcpy(msg, uv ? "hmacuv" : "hmac", l);
    memcpy(msg + l, rp_hash, 32);
    memcpy(msg + l + 32, cred_id, 32);
    return store_kdf(msg, l + 64, out);
}

static mbedtls_svc_key_id_t s_ka[2];   /* key-agreement key per PIN/UV auth protocol (index proto - 1) */

esp_err_t cred_ka_regen(void)
{
    for (int i = 0; i < 2; i++) {
        psa_destroy_key(s_ka[i]);
        s_ka[i] = MBEDTLS_SVC_KEY_ID_INIT;
        psa_status_t st = PSA_ERROR_INVALID_ARGUMENT;
        for (int tries = 0; tries < 8 && st == PSA_ERROR_INVALID_ARGUMENT; tries++) {
            uint8_t sk[32];
            cred_rng(sk, sizeof(sk));
            st = import_p256(sk, PSA_KEY_USAGE_DERIVE, PSA_ALG_ECDH, &s_ka[i]);
            mbedtls_platform_zeroize(sk, sizeof(sk));
        }
        if (st != PSA_SUCCESS) {
            ESP_LOGE(TAG, "key agreement keygen: %d", (int)st);
            s_ka[i] = MBEDTLS_SVC_KEY_ID_INIT;
            return ESP_FAIL;
        }
    }
    return ESP_OK;
}

esp_err_t cred_ka_public(int proto, uint8_t pub[65])
{
    if (proto != 1 && proto != 2) return ESP_ERR_INVALID_ARG;
    size_t olen = 0;
    psa_status_t st = psa_export_public_key(s_ka[proto - 1], pub, 65, &olen);
    if (st != PSA_SUCCESS) ESP_LOGE(TAG, "key agreement export: %d", (int)st);
    return (st == PSA_SUCCESS && olen == 65) ? ESP_OK : ESP_FAIL;
}

esp_err_t cred_ka_shared(int proto, const uint8_t peer[65], uint8_t ss[64])
{
    if (proto != 1 && proto != 2) return ESP_ERR_INVALID_ARG;
    uint8_t z[32];
    size_t zlen = 0;
    /* PSA loads the peer point with mbedtls_ecp_check_pubkey(): off-curve or infinity is rejected. */
    psa_status_t st = psa_raw_key_agreement(PSA_ALG_ECDH, s_ka[proto - 1], peer, 65, z, sizeof(z), &zlen);
    if (st != PSA_SUCCESS || zlen != 32) {
        ESP_LOGW(TAG, "ecdh: %d", (int)st);
        mbedtls_platform_zeroize(z, sizeof(z));
        return st == PSA_ERROR_INVALID_ARGUMENT ? ESP_ERR_INVALID_ARG : ESP_FAIL;
    }
    esp_err_t err;
    if (proto == 1) {
        err = cred_sha256(z, 32, ss);                     /* kdf(Z) = SHA-256(Z) */
    } else {
        /* Two HKDF-SHA-256 runs, L = 32, salt = 32 zero bytes: PRK = HMAC(salt, Z), OKM = HMAC(PRK, info || 0x01). */
        static const uint8_t zero[32];
        static const char info_h[] = "CTAP2 HMAC key\x01";
        static const char info_a[] = "CTAP2 AES key\x01";
        uint8_t prk[32];
        err = cred_hmac(zero, z, 32, prk);
        if (err == ESP_OK) err = cred_hmac(prk, (const uint8_t *)info_h, sizeof(info_h) - 1, ss);
        if (err == ESP_OK) err = cred_hmac(prk, (const uint8_t *)info_a, sizeof(info_a) - 1, ss + 32);
        mbedtls_platform_zeroize(prk, sizeof(prk));
    }
    mbedtls_platform_zeroize(z, sizeof(z));
    return err;
}
