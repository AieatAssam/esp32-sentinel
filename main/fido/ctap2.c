#include <stdbool.h>
#include <string.h>
#include "cbor.h"
#include "esp_log.h"
#include "esp_random.h"
#include "mbedtls/platform_util.h"
#include "esp_timer.h"
#include "nvs.h"
#include "cred.h"
#include "ctaphid.h"
#include "cbor_check.h"
#include "fido_priv.h"
#include "store.h"
#include "ctap2.h"

static const char *TAG = "ctap2";

#define ST_OK                 0x00
#define ST_INVALID_CMD        0x01
#define ST_INVALID_PAR        0x02
#define ST_INVALID_LEN        0x03
#define ST_OTHER              0x7f
#define ST_CBOR_TYPE          0x11
#define ST_CBOR               0x12
#define ST_MISSING            0x14
#define ST_CRED_EXCLUDED      0x19
#define ST_UNSUPPORTED_ALG    0x26
#define ST_NO_CREDENTIALS     0x2e
#define ST_NOT_ALLOWED        0x30
#define ST_UNSUPPORTED_OPTION 0x2b
#define ST_PIN_NOT_SET        0x35
#define ST_KEY_STORE_FULL     0x28
#define ST_PIN_AUTH_INVALID   0x33
#define ST_INVALID_SUBCMD     0x3e
#define ST_INVALID_OPTION     0x2c
#define ST_PIN_INVALID        0x31
#define ST_PIN_BLOCKED        0x32
#define ST_PIN_AUTH_BLOCKED   0x34
#define ST_PUAT_REQUIRED      0x36
#define ST_PIN_POLICY         0x37
#define ST_UNAUTH_PERMISSION  0x40

static const uint8_t k_aaguid[16] = {0xa3, 0xed, 0xf5, 0x39, 0x29, 0xe0, 0x5a, 0xbf,
                                     0x64, 0x59, 0x94, 0x62, 0x32, 0x7a, 0x45, 0xe8};

/* Static: this module runs on the single fido task only. */
static uint8_t s_authdata[256];
static uint8_t s_cose[96];

/* ---- CBOR request helpers ---- */

/* Finds the entry for an integer key (tk == NULL) or a text key in a map. */
static bool mfind(const CborValue *m, int64_t ik, const char *tk, CborValue *val)
{
    /* Iterate the entries inside the map, not the map value itself (advancing the map value
     * would skip the whole map and every lookup would miss). */
    CborValue it;
    if (!cbor_value_is_map(m) || cbor_value_enter_container(m, &it) != CborNoError) return false;
    while (!cbor_value_at_end(&it)) {
        CborValue k = it;
        if (cbor_value_advance(&it) != CborNoError || cbor_value_at_end(&it)) return false;
        CborValue v = it;
        if (cbor_value_advance(&it) != CborNoError) return false;
        if (tk == NULL) {
            int64_t kv;
            if (cbor_value_is_integer(&k) && cbor_value_get_int64(&k, &kv) == CborNoError && kv == ik) {
                *val = v;
                return true;
            }
        } else if (cbor_value_is_text_string(&k)) {
            bool eq = false;
            if (cbor_value_text_string_equals(&k, tk, &eq) == CborNoError && eq) {
                *val = v;
                return true;
            }
        }
    }
    return false;
}

/* Copies a byte string into dst (capacity max); *len receives its length. */
static bool get_bytes(const CborValue *v, uint8_t *dst, size_t max, size_t *len)
{
    if (!cbor_value_is_byte_string(v)) return false;
    size_t n = 0;
    if (cbor_value_get_string_length(v, &n) != CborNoError || n > max) return false;
    size_t copy = n;
    if (cbor_value_copy_byte_string(v, dst, &copy, NULL) != CborNoError) return false;
    *len = n;
    return true;
}

static bool get_text(const CborValue *v, char *dst, size_t max, size_t *len)
{
    if (!cbor_value_is_text_string(v)) return false;
    size_t n = 0;
    if (cbor_value_get_string_length(v, &n) != CborNoError || n + 1 > max) return false;
    size_t copy = n + 1;
    if (cbor_value_copy_text_string(v, dst, &copy, NULL) != CborNoError) return false;
    *len = n;
    return true;
}

static bool get_bool(const CborValue *v, bool *b)
{
    return cbor_value_is_boolean(v) && cbor_value_get_boolean(v, b) == CborNoError;
}

static bool get_uint(const CborValue *v, int64_t *out)
{
    return cbor_value_is_unsigned_integer(v) && cbor_value_get_int64(v, out) == CborNoError;
}

static uint8_t sha_rp(const uint8_t *id, size_t id_len, uint8_t out[32])
{
    return cred_sha256(id, id_len, out) == ESP_OK ? ST_OK : ST_OTHER;
}

/* ---- response helpers ---- */

typedef struct {
    CborEncoder enc;
    uint8_t *out;
    size_t cap;
} resp_t;

static void resp_begin(resp_t *r, uint8_t *out, size_t cap)
{
    out[0] = ST_OK;
    r->out = out;
    r->cap = cap;
    cbor_encoder_init(&r->enc, out + 1, cap - 1, 0);
}

static size_t resp_end(resp_t *r)
{
    return 1 + cbor_encoder_get_buffer_size(&r->enc, r->out + 1);
}

/* P-256 COSE_Key {1:2, 3:alg, -1:1, -2:x, -3:y}, keys in canonical order. alg is -7 (ES256) for
 * credentials, -25 for the PIN/UV key-agreement key. Note: tinycbor's cbor_encode_negative_int(n)
 * encodes -n, not -1-n, so negative values go through cbor_encode_int. */
static void cose_key_enc(CborEncoder *parent, const uint8_t pub[65], int64_t alg)
{
    CborEncoder map;
    cbor_encoder_create_map(parent, &map, 5);
    cbor_encode_int(&map, 1);
    cbor_encode_int(&map, 2);
    cbor_encode_int(&map, 3);
    cbor_encode_int(&map, alg);
    cbor_encode_int(&map, -1);
    cbor_encode_int(&map, 1);
    cbor_encode_int(&map, -2);
    cbor_encode_byte_string(&map, pub + 1, 32);
    cbor_encode_int(&map, -3);
    cbor_encode_byte_string(&map, pub + 33, 32);
    cbor_encoder_close_container(parent, &map);
}

static size_t cose_key(const uint8_t pub[65], uint8_t *buf, size_t cap)
{
    CborEncoder enc;
    cbor_encoder_init(&enc, buf, cap, 0);
    cose_key_enc(&enc, pub, -7);
    return cbor_encoder_get_buffer_size(&enc, buf);
}


/* ---- hmac-secret ---- */

/* getAssertion extension input, checked for shape before the presence wait. */
typedef struct {
    uint8_t proto;          /* 0: extension not requested */
    uint8_t peer[65];       /* platform key-agreement key, uncompressed */
    uint8_t enc[16 + 64];   /* saltEnc */
    size_t enc_len;
    uint8_t auth[32];       /* saltAuth */
    size_t auth_len;
} hs_req_t;

/* Shared secret and decrypted salts, kept for getNextAssertion. Wiped with mbedtls_platform_zeroize. */
typedef struct {
    uint8_t proto;          /* 0: no hmac-secret output */
    uint8_t nsalt;          /* 1 or 2 */
    bool uv;                /* use CredRandomWithUV */
    uint8_t ss[64];         /* v1: 32 bytes; v2: HMAC key || AES key */
    uint8_t salt[64];
} hs_t;

static bool coord(const CborValue *ka, int64_t key, uint8_t out[32])
{
    CborValue v;
    size_t n = 0;
    return mfind(ka, key, NULL, &v) && get_bytes(&v, out, 32, &n) && n == 32;
}

/* COSE_Key of a platform key-agreement key: EC2 (kty 2), P-256 (crv 1), x and y. peer gets 04||x||y. */
static bool parse_peer(const CborValue *ka, uint8_t peer[65])
{
    int64_t kty = 0, crv = 0;
    CborValue t;
    if (!mfind(ka, 1, NULL, &t) || !get_uint(&t, &kty) || kty != 2 || !mfind(ka, -1, NULL, &t) ||
        !get_uint(&t, &crv) || crv != 1 || !coord(ka, -2, peer + 1) || !coord(ka, -3, peer + 33)) {
        return false;
    }
    peer[0] = 0x04;
    return true;
}

static uint8_t hs_parse(const CborValue *m, hs_req_t *q)
{
    memset(q, 0, sizeof(*q));
    CborValue ext, hs, v, ka;
    if (!mfind(m, 4, NULL, &ext)) return ST_OK;
    if (!cbor_value_is_map(&ext)) return ST_CBOR_TYPE;
    if (!mfind(&ext, 0, "hmac-secret", &hs)) return ST_OK;
    if (!cbor_value_is_map(&hs)) return ST_CBOR_TYPE;

    int64_t proto = 1;   /* absent means protocol 1 */
    if (mfind(&hs, 4, NULL, &v)) {
        if (!get_uint(&v, &proto)) return ST_CBOR_TYPE;
        if (proto != 1 && proto != 2) return ST_INVALID_PAR;
    }
    if (!mfind(&hs, 1, NULL, &ka) || !mfind(&hs, 2, NULL, &v)) return ST_MISSING;
    if (!cbor_value_is_map(&ka)) return ST_CBOR_TYPE;
    if (!parse_peer(&ka, q->peer)) return ST_INVALID_PAR;

    if (!cbor_value_is_byte_string(&v)) return ST_CBOR_TYPE;
    size_t iv = (proto == 2) ? 16 : 0;
    if (!get_bytes(&v, q->enc, sizeof(q->enc), &q->enc_len) ||
        (q->enc_len != iv + 32 && q->enc_len != iv + 64)) {
        return ST_INVALID_PAR;   /* decrypt would fail or give neither 32 nor 64 bytes */
    }
    if (!mfind(&hs, 3, NULL, &v)) return ST_MISSING;
    if (!cbor_value_is_byte_string(&v)) return ST_CBOR_TYPE;
    if (!get_bytes(&v, q->auth, sizeof(q->auth), &q->auth_len)) q->auth_len = 0;   /* too long: verify fails */
    q->proto = (uint8_t)proto;
    return ST_OK;
}

/* decapsulate, verify(saltAuth) in constant time, then decrypt the salts. Runs after the presence check. */
static uint8_t hs_open(const hs_req_t *q, hs_t *hs)
{
    esp_err_t err = cred_ka_shared(q->proto, q->peer, hs->ss);
    if (err == ESP_ERR_INVALID_ARG) return ST_INVALID_PAR;
    if (err != ESP_OK) return ST_OTHER;

    uint8_t mac[32];
    if (cred_hmac(hs->ss, q->enc, q->enc_len, mac) != ESP_OK) return ST_OTHER;
    size_t want = (q->proto == 2) ? 32 : 16;   /* v1 MAC is truncated to 16 bytes */
    uint8_t diff = (uint8_t)(q->auth_len != want);
    for (size_t i = 0; i < want; i++) diff |= mac[i] ^ q->auth[i];
    mbedtls_platform_zeroize(mac, sizeof(mac));
    if (diff) return ST_PIN_AUTH_INVALID;

    static const uint8_t zero_iv[16];
    const uint8_t *key = (q->proto == 2) ? hs->ss + 32 : hs->ss;
    const uint8_t *iv = (q->proto == 2) ? q->enc : zero_iv;
    const uint8_t *ct = (q->proto == 2) ? q->enc + 16 : q->enc;
    size_t n = (q->proto == 2) ? q->enc_len - 16 : q->enc_len;
    if (cred_aes_cbc(false, key, iv, ct, n, hs->salt) != ESP_OK) return ST_INVALID_PAR;
    hs->nsalt = (uint8_t)(n / 32);
    hs->proto = q->proto;
    return ST_OK;
}

/* encrypt(shared secret, output1 [|| output2]) with output_i = HMAC(CredRandom, salt_i). out holds 80 bytes. */
static uint8_t hs_output(const hs_t *hs, const uint8_t rp_hash[32], const uint8_t cred_id[FIDO_CRED_ID_LEN],
                         uint8_t out[80], size_t *out_len)
{
    uint8_t cr[32], plain[64];
    size_t n = 32u * hs->nsalt;
    uint8_t st = ST_OTHER;
    if (cred_hmac_secret(rp_hash, cred_id, hs->uv, cr) != ESP_OK) goto done;
    for (size_t i = 0; i < hs->nsalt; i++) {
        if (cred_hmac(cr, hs->salt + 32 * i, 32, plain + 32 * i) != ESP_OK) goto done;
    }
    if (hs->proto == 2) {
        esp_fill_random(out, 16);
        if (cred_aes_cbc(true, hs->ss + 32, out, plain, n, out + 16) != ESP_OK) goto done;
        *out_len = 16 + n;
    } else {
        static const uint8_t zero_iv[16];
        if (cred_aes_cbc(true, hs->ss, zero_iv, plain, n, out) != ESP_OK) goto done;
        *out_len = n;
    }
    st = ST_OK;
done:
    mbedtls_platform_zeroize(cr, sizeof(cr));
    mbedtls_platform_zeroize(plain, sizeof(plain));
    return st;
}

/* ---- request field helpers (CTAP 2.1 §8: missing top-level parameter -> MISSING_PARAMETER, wrong type
 * or a structure missing a required member -> CBOR_UNEXPECTED_TYPE) ---- */

static uint8_t need_bytes(const CborValue *m, int64_t key, uint8_t *dst, size_t want)
{
    CborValue v;
    size_t n = 0;
    if (!mfind(m, key, NULL, &v)) return ST_MISSING;
    if (!cbor_value_is_byte_string(&v)) return ST_CBOR_TYPE;
    if (!get_bytes(&v, dst, want, &n) || n != want) return ST_INVALID_PAR;
    return ST_OK;
}

/* Optional text member of an entity map: absent is fine, wrong type is an error. Truncated to max - 1 bytes
 * at a UTF-8 code point boundary (WebAuthn lets authenticators truncate name/displayName). */
static uint8_t opt_text(const CborValue *map, const char *name, char *dst, size_t max, uint8_t *len)
{
    CborValue v;
    *len = 0;
    if (!mfind(map, 0, name, &v)) return ST_OK;
    if (!cbor_value_is_text_string(&v)) return ST_CBOR_TYPE;
    char buf[300];
    size_t n = 0;
    if (!get_text(&v, buf, sizeof(buf), &n)) n = 0, buf[0] = 0;   /* absurdly long: drop it */
    if (n > max - 1) {
        n = max - 1;
        while (n > 0 && ((uint8_t)buf[n] & 0xc0) == 0x80) n--;   /* do not split a code point */
    }
    memcpy(dst, buf, n);
    *len = (uint8_t)n;
    return ST_OK;
}

/* options map: returns status; *val is -1 absent, 0 false, 1 true for each requested key. */
static uint8_t get_opts(const CborValue *m, int64_t key, int *up, int *uv, int *rk)
{
    *up = *uv = *rk = -1;
    CborValue o;
    if (!mfind(m, key, NULL, &o)) return ST_OK;
    if (!cbor_value_is_map(&o)) return ST_CBOR_TYPE;
    const char *names[3] = {"up", "uv", "rk"};
    int *outs[3] = {up, uv, rk};
    for (int i = 0; i < 3; i++) {
        CborValue v;
        bool b;
        if (!mfind(&o, 0, names[i], &v)) continue;
        if (!get_bool(&v, &b)) return ST_CBOR_TYPE;
        *outs[i] = b ? 1 : 0;
    }
    return ST_OK;
}

/* Walks a list of PublicKeyCredentialDescriptor. For each element whose id is one of ours for rp_hash,
 * calls fn (stops when it returns true). Wrong shapes are CBOR_UNEXPECTED_TYPE. *count gets the length. */
typedef bool (*desc_fn)(const uint8_t id[FIDO_CRED_ID_LEN], void *ctx);
static uint8_t walk_desc(const CborValue *list, const uint8_t rp_hash[32], desc_fn fn, void *ctx, size_t *count)
{
    *count = 0;
    if (!cbor_value_is_array(list)) return ST_CBOR_TYPE;
    CborValue it;
    if (cbor_value_enter_container(list, &it) != CborNoError) return ST_CBOR;
    bool stop = false;
    while (!cbor_value_at_end(&it)) {
        CborValue e = it, idv, tv;
        if (cbor_value_advance(&it) != CborNoError) return ST_CBOR;
        (*count)++;
        if (!cbor_value_is_map(&e) || !mfind(&e, 0, "id", &idv) || !cbor_value_is_byte_string(&idv) ||
            !mfind(&e, 0, "type", &tv) || !cbor_value_is_text_string(&tv)) {
            return ST_CBOR_TYPE;
        }
        bool pk = false;
        cbor_value_text_string_equals(&tv, "public-key", &pk);
        uint8_t id[64];
        size_t idl = 0;
        if (stop || !pk || !get_bytes(&idv, id, sizeof(id), &idl)) continue;
        if (idl == FIDO_CRED_ID_LEN && cred_id_is_ours(rp_hash, id, idl)) stop = fn(id, ctx);
    }
    return ST_OK;
}

/* rpId per CTAP 2.1 §6.8.7 for display storage (comparisons always use the full rpIdHash). */
static uint8_t store_rpid(const char *rpid, size_t len, char out[FIDO_RPID_MAX])
{
    if (len <= FIDO_RPID_MAX) {
        memcpy(out, rpid, len);
        return (uint8_t)len;
    }
    size_t used = 0;
    const char *colon = memchr(rpid, ':', len);
    if (colon) {
        size_t pl = (size_t)(colon - rpid) + 1;
        used = pl <= FIDO_RPID_MAX ? pl : FIDO_RPID_MAX;
        memcpy(out, rpid, used);
    }
    if (FIDO_RPID_MAX - used < 3) return (uint8_t)used;
    out[used++] = (char)0xe2;
    out[used++] = (char)0x80;
    out[used++] = (char)0xa6;
    size_t tc = FIDO_RPID_MAX - used;
    memcpy(out + used, rpid + len - tc, tc);
    return FIDO_RPID_MAX;
}

/* ---- getInfo (0x04) ---- */

#define MAX_CRED_IN_LIST 8
#define PIN_MIN_CP       4    /* minimum PIN length, code points (2.1 default) */
#define PIN_MAX_BYTES    63

static store_pin_t s_pin;   /* clientPIN state, loaded at boot */

/* Versions: FIDO_2_1 is advertised because every CTAP 2.1 mandatory feature for an authenticator with
 * rk=true is present (2.1 §9 "Mandatory features"): hmac-secret, clientPin, credMgmt, credProtect,
 * pinUvAuthToken and PIN/UV auth protocol 2, plus authenticatorSelection. FIDO_2_0 stays for older
 * platforms. There is no built-in UV, so there is no "uv" option. */
static uint8_t cmd_get_info(resp_t *r)
{
    CborEncoder map, arr, opts, alg;
    cbor_encoder_create_map(&r->enc, &map, 11);
    cbor_encode_int(&map, 1);
    cbor_encoder_create_array(&map, &arr, 3);
    cbor_encode_text_stringz(&arr, "U2F_V2");
    cbor_encode_text_stringz(&arr, "FIDO_2_0");
    cbor_encode_text_stringz(&arr, "FIDO_2_1");
    cbor_encoder_close_container(&map, &arr);
    cbor_encode_int(&map, 2);
    cbor_encoder_create_array(&map, &arr, 2);
    cbor_encode_text_stringz(&arr, "credProtect");
    cbor_encode_text_stringz(&arr, "hmac-secret");
    cbor_encoder_close_container(&map, &arr);
    cbor_encode_int(&map, 3);
    cbor_encode_byte_string(&map, k_aaguid, sizeof(k_aaguid));
    cbor_encode_int(&map, 4);
    cbor_encoder_create_map(&map, &opts, 7);   /* canonical order: shorter keys first, then bytewise */
    cbor_encode_text_stringz(&opts, "rk");
    cbor_encode_boolean(&opts, true);
    cbor_encode_text_stringz(&opts, "up");
    cbor_encode_boolean(&opts, true);
    cbor_encode_text_stringz(&opts, "plat");
    cbor_encode_boolean(&opts, false);
    cbor_encode_text_stringz(&opts, "credMgmt");
    cbor_encode_boolean(&opts, true);
    cbor_encode_text_stringz(&opts, "clientPin");
    cbor_encode_boolean(&opts, s_pin.set);          /* false: supported, not set yet */
    cbor_encode_text_stringz(&opts, "pinUvAuthToken");
    cbor_encode_boolean(&opts, true);
    cbor_encode_text_stringz(&opts, "makeCredUvNotRqd");
    cbor_encode_boolean(&opts, true);               /* non-discoverable credentials need no PIN */
    cbor_encoder_close_container(&map, &opts);
    cbor_encode_int(&map, 5);
    cbor_encode_int(&map, CTAPHID_MAX_MSG);
    cbor_encode_int(&map, 6);
    cbor_encoder_create_array(&map, &arr, 2);
    cbor_encode_int(&arr, 2);
    cbor_encode_int(&arr, 1);
    cbor_encoder_close_container(&map, &arr);
    /* maxCredentialCountInList / maxCredentialIdLength: lets platforms batch allow/exclude lists. */
    cbor_encode_int(&map, 7);
    cbor_encode_int(&map, MAX_CRED_IN_LIST);
    cbor_encode_int(&map, 8);
    cbor_encode_int(&map, FIDO_CRED_ID_LEN);
    cbor_encode_int(&map, 9);
    cbor_encoder_create_array(&map, &arr, 1);
    cbor_encode_text_stringz(&arr, "usb");
    cbor_encoder_close_container(&map, &arr);
    cbor_encode_int(&map, 10);
    cbor_encoder_create_array(&map, &arr, 1);
    cbor_encoder_create_map(&arr, &alg, 2);
    cbor_encode_text_stringz(&alg, "alg");
    cbor_encode_int(&alg, -7);
    cbor_encode_text_stringz(&alg, "type");
    cbor_encode_text_stringz(&alg, "public-key");
    cbor_encoder_close_container(&arr, &alg);
    cbor_encoder_close_container(&map, &arr);
    cbor_encode_int(&map, 13);
    cbor_encode_int(&map, s_pin.min_len > PIN_MIN_CP ? s_pin.min_len : PIN_MIN_CP);
    cbor_encoder_close_container(&r->enc, &map);
    return ST_OK;
}

/* ---- PIN and pinUvAuthToken (CTAP 2.1 §6.5) ----
 * The PIN is kept as LEFT(SHA-256(PIN), 16), encrypted and MACed under keys derived from the master
 * (store.c). Limit: without flash encryption the master sits in NVS next to that record, so whoever can
 * read the flash can test PIN guesses offline at SHA-256 speed; the 8-try counter only protects against
 * guessing through the USB interface. Burning the eFuse HMAC key (harden) moves the master out of flash. */

#define PERM_MC        0x01
#define PERM_GA        0x02
#define PERM_CM        0x04
#define PERM_KNOWN     0x3f   /* mc ga cm be lbw acfg */
#define PERM_SUPPORTED (PERM_MC | PERM_GA | PERM_CM)
#define TOKEN_IDLE_US  30000000LL    /* initial usage limit for USB, kept rolling: 30 s after the last use */
#define TOKEN_MAX_US   600000000LL   /* max usage period */
#define PIN_MAX_CONSEC 3             /* wrong PINs in a row before a power cycle is needed */

static uint8_t s_consec;                  /* wrong PINs since power-up, reset by a right one */
static volatile bool s_pin_set_cache;     /* copies for other tasks (fido.h) */
static volatile uint8_t s_pin_retries_cache;

typedef struct {
    bool in_use;
    uint8_t perms;
    bool has_rp;                          /* permissions RP ID, kept as its hash */
    uint8_t rp_hash[32];
    int64_t start_us, last_us;
    uint8_t key[32];
} token_t;
static token_t s_tok;

static void cm_clear(void);

static void token_stop(void)
{
    mbedtls_platform_zeroize(&s_tok, sizeof(s_tok));
}

/* False once the token expired (it is then wiped, with any credentialManagement state it authorised). */
static bool token_live(void)
{
    if (!s_tok.in_use) return false;
    int64_t now = esp_timer_get_time();
    if (now - s_tok.last_us > TOKEN_IDLE_US || now - s_tok.start_us > TOKEN_MAX_US) {
        token_stop();
        cm_clear();
        return false;
    }
    return true;
}

static esp_err_t pin_save(void)
{
    s_pin_set_cache = s_pin.set;
    s_pin_retries_cache = s_pin.retries;
    return store_pin_save(&s_pin);
}

bool fido_pin_is_set(void)
{
    return s_pin_set_cache;
}

uint8_t fido_pin_retries(void)
{
    return s_pin_retries_cache;
}

/* PIN/UV auth protocol primitives (2.1 §6.5.6, §6.5.7). ss from cred_ka_shared(): v1 32 bytes,
 * v2 HMAC key || AES key. The HMAC key is ss[0..32) in both. */
static const uint8_t *pp_akey(uint8_t proto, const uint8_t *ss)
{
    return proto == 2 ? ss + 32 : ss;
}

/* verify(): v1 compares the first 16 bytes of the HMAC, v2 all 32. Constant time. */
static bool pp_verify(uint8_t proto, const uint8_t key[32], const uint8_t *msg, size_t len, const uint8_t *sig,
                      size_t sig_len)
{
    uint8_t mac[32];
    size_t want = proto == 2 ? 32 : 16;
    bool ok = cred_hmac(key, msg, len, mac) == ESP_OK && sig_len == want && cred_ct_equal(mac, sig, want);
    mbedtls_platform_zeroize(mac, sizeof(mac));
    return ok;
}

static bool pp_decrypt(uint8_t proto, const uint8_t *ss, const uint8_t *ct, size_t len, uint8_t *out, size_t *out_len)
{
    static const uint8_t zero_iv[16];
    const uint8_t *iv = zero_iv;
    if (proto == 2) {
        if (len < 16) return false;
        iv = ct;
        ct += 16;
        len -= 16;
    }
    if (len == 0 || len % 16) return false;
    if (cred_aes_cbc(false, pp_akey(proto, ss), iv, ct, len, out) != ESP_OK) return false;
    *out_len = len;
    return true;
}

static bool pp_encrypt(uint8_t proto, const uint8_t *ss, const uint8_t *in, size_t len, uint8_t *out, size_t *out_len)
{
    static const uint8_t zero_iv[16];
    if (proto == 2) {
        esp_fill_random(out, 16);
        *out_len = 16 + len;
        return cred_aes_cbc(true, pp_akey(proto, ss), out, in, len, out + 16) == ESP_OK;
    }
    *out_len = len;
    return cred_aes_cbc(true, ss, zero_iv, in, len, out) == ESP_OK;
}

/* Byte-string member of m: MISSING, CBOR_UNEXPECTED_TYPE, or INVALID_PARAMETER when longer than max. */
static uint8_t get_bstr(const CborValue *m, int64_t key, uint8_t *dst, size_t max, size_t *len)
{
    CborValue v;
    if (!mfind(m, key, NULL, &v)) return ST_MISSING;
    if (!cbor_value_is_byte_string(&v)) return ST_CBOR_TYPE;
    return get_bytes(&v, dst, max, len) ? ST_OK : ST_INVALID_PAR;
}

/* decapsulate(keyAgreement) into ss. */
static uint8_t cp_shared(const CborValue *m, uint8_t proto, uint8_t ss[64])
{
    CborValue ka;
    uint8_t peer[65];
    if (!mfind(m, 3, NULL, &ka)) return ST_MISSING;
    if (!cbor_value_is_map(&ka)) return ST_CBOR_TYPE;
    if (!parse_peer(&ka, peer)) return ST_INVALID_PAR;
    esp_err_t err = cred_ka_shared(proto, peer, ss);
    return err == ESP_OK ? ST_OK : err == ESP_ERR_INVALID_ARG ? ST_INVALID_PAR : ST_OTHER;
}

/* Gate for every PIN attempt. */
static uint8_t pin_attempt_allowed(void)
{
    if (!s_pin.set) return ST_PIN_NOT_SET;
    if (s_pin.retries == 0) return ST_PIN_BLOCKED;
    if (s_consec >= PIN_MAX_CONSEC) return ST_PIN_AUTH_BLOCKED;
    return ST_OK;
}

/* Checks pinHashEnc against the stored PIN hash. The retry counter is decremented and committed to flash
 * before the comparison, so cutting power mid-check cannot save a guess. */
static uint8_t pin_verify_hash(uint8_t proto, const uint8_t ss[64], const uint8_t *enc, size_t enc_len)
{
    s_pin.retries--;
    if (pin_save() != ESP_OK) return ST_OTHER;
    uint8_t plain[32];
    size_t n = 0;
    /* pinHashEnc is exactly 16 bytes (v1) or IV || 16 (v2); any other length counts as a wrong PIN. */
    bool ok = enc_len == (proto == 2 ? 32u : 16u) && pp_decrypt(proto, ss, enc, enc_len, plain, &n) && n == 16 &&
              cred_ct_equal(plain, s_pin.hash, 16);
    mbedtls_platform_zeroize(plain, sizeof(plain));
    if (!ok) {
        cred_ka_regen();   /* a wrong PIN gets a new key agreement key (regenerate()) */
        s_consec++;
        ESP_LOGW(TAG, "wrong PIN, %u retries left", s_pin.retries);
        if (s_pin.retries == 0) return ST_PIN_BLOCKED;
        if (s_consec >= PIN_MAX_CONSEC) return ST_PIN_AUTH_BLOCKED;
        return ST_PIN_INVALID;
    }
    s_consec = 0;
    s_pin.retries = STORE_PIN_RETRIES;
    return pin_save() == ESP_OK ? ST_OK : ST_OTHER;
}

/* Decrypts newPinEnc (64 bytes padded with 0x00) and applies the policy: at least the minimum length in
 * code points, at most 63 bytes. hash16 gets LEFT(SHA-256(PIN), 16). */
static uint8_t new_pin_hash(uint8_t proto, const uint8_t ss[64], const uint8_t *enc, size_t enc_len,
                            uint8_t hash16[16])
{
    uint8_t pin[64], h[32];
    size_t n = 0, len = 64, cps = 0;
    uint8_t st = ST_OK;
    /* paddedNewPin must be 64 bytes: newPinEnc is exactly 64 (v1) or IV || 64 (v2). Checked before
     * decrypting, so pin[] never receives more than 64 bytes. */
    if (enc_len != (proto == 2 ? 80u : 64u)) {
        st = ST_INVALID_PAR;
        goto out;
    }
    if (!pp_decrypt(proto, ss, enc, enc_len, pin, &n) || n != 64) {
        st = ST_OTHER;
        goto out;
    }
    while (len > 0 && pin[len - 1] == 0) len--;
    for (size_t i = 0; i < len; i++) cps += (pin[i] & 0xc0) != 0x80;
    if (len > PIN_MAX_BYTES || cps < (s_pin.min_len > PIN_MIN_CP ? s_pin.min_len : PIN_MIN_CP)) {
        st = ST_PIN_POLICY;
        goto out;
    }
    if (cred_sha256(pin, len, h) != ESP_OK) {
        st = ST_OTHER;
        goto out;
    }
    memcpy(hash16, h, 16);
out:
    mbedtls_platform_zeroize(pin, sizeof(pin));
    mbedtls_platform_zeroize(h, sizeof(h));
    return st;
}

static uint8_t cp_set_pin(const CborValue *m, uint8_t proto)
{
    uint8_t ss[64], enc[80], auth[32], hash[16];
    size_t enc_len = 0, auth_len = 0;
    CborValue v;
    uint8_t st;
    if (!mfind(m, 3, NULL, &v)) return ST_MISSING;
    if ((st = get_bstr(m, 5, enc, sizeof(enc), &enc_len)) != ST_OK) return st;
    if ((st = get_bstr(m, 4, auth, sizeof(auth), &auth_len)) == ST_MISSING || st == ST_CBOR_TYPE) return st;
    if (st != ST_OK) auth_len = 0;   /* too long: verify fails */
    if (s_pin.set) return ST_PIN_AUTH_INVALID;
    if ((st = cp_shared(m, proto, ss)) != ST_OK) goto out;
    if (!pp_verify(proto, ss, enc, enc_len, auth, auth_len)) {
        st = ST_PIN_AUTH_INVALID;
        goto out;
    }
    if ((st = new_pin_hash(proto, ss, enc, enc_len, hash)) != ST_OK) goto out;
    s_pin.set = true;
    s_pin.retries = STORE_PIN_RETRIES;
    memcpy(s_pin.hash, hash, 16);
    s_consec = 0;
    st = pin_save() == ESP_OK ? ST_OK : ST_OTHER;
out:
    mbedtls_platform_zeroize(ss, sizeof(ss));
    mbedtls_platform_zeroize(hash, sizeof(hash));
    return st;
}

static uint8_t cp_change_pin(const CborValue *m, uint8_t proto)
{
    uint8_t ss[64], buf[80 + 32], auth[32], hash[16];
    size_t enc_len = 0, ph_len = 0, auth_len = 0;
    CborValue v;
    uint8_t st;
    if (!mfind(m, 3, NULL, &v)) return ST_MISSING;
    if ((st = get_bstr(m, 5, buf, 80, &enc_len)) != ST_OK) return st;
    if ((st = get_bstr(m, 6, buf + enc_len, 32, &ph_len)) != ST_OK) return st;
    if ((st = get_bstr(m, 4, auth, sizeof(auth), &auth_len)) == ST_MISSING || st == ST_CBOR_TYPE) return st;
    if (st != ST_OK) auth_len = 0;   /* too long: verify fails */
    if ((st = pin_attempt_allowed()) != ST_OK) return st;
    if ((st = cp_shared(m, proto, ss)) != ST_OK) goto out;
    if (!pp_verify(proto, ss, buf, enc_len + ph_len, auth, auth_len)) {   /* over newPinEnc || pinHashEnc */
        st = ST_PIN_AUTH_INVALID;
        goto out;
    }
    if ((st = pin_verify_hash(proto, ss, buf + enc_len, ph_len)) != ST_OK) goto out;
    if ((st = new_pin_hash(proto, ss, buf, enc_len, hash)) != ST_OK) goto out;
    memcpy(s_pin.hash, hash, 16);
    token_stop();   /* resetPinUvAuthToken(): tokens issued under the old PIN die */
    cm_clear();
    st = pin_save() == ESP_OK ? ST_OK : ST_OTHER;
out:
    mbedtls_platform_zeroize(ss, sizeof(ss));
    mbedtls_platform_zeroize(hash, sizeof(hash));
    return st;
}

/* getPinToken (0x05: mc+ga, no RP ID) and getPinUvAuthTokenUsingPinWithPermissions (0x09). */
static uint8_t cp_get_token(const CborValue *m, uint8_t proto, int64_t sub, resp_t *r)
{
    uint8_t ss[64], ph[48], out[48];
    size_t ph_len = 0, out_len = 0;
    CborValue v, pv, rv;
    uint8_t st;
    int64_t perms = PERM_MC | PERM_GA;
    bool has_rp = mfind(m, 10, NULL, &rv);
    uint8_t rp_hash[32];
    if (!mfind(m, 3, NULL, &v)) return ST_MISSING;
    if ((st = get_bstr(m, 6, ph, sizeof(ph), &ph_len)) != ST_OK) return st;
    if (sub == 0x05) {
        if (mfind(m, 9, NULL, &pv) || has_rp) return ST_INVALID_PAR;
    } else {
        if (!mfind(m, 9, NULL, &pv)) return ST_MISSING;
        if (!get_uint(&pv, &perms)) return ST_CBOR_TYPE;
        if (perms == 0) return ST_INVALID_PAR;
        if (perms & PERM_KNOWN & ~PERM_SUPPORTED) return ST_UNAUTH_PERMISSION;   /* be, lbw, acfg */
        perms &= PERM_SUPPORTED;                                                 /* undefined bits ignored */
        if (has_rp) {
            char rpid[256];
            size_t n = 0;
            if (!cbor_value_is_text_string(&rv)) return ST_CBOR_TYPE;
            if (!get_text(&rv, rpid, sizeof(rpid), &n) || n == 0) return ST_INVALID_PAR;
            if (sha_rp((const uint8_t *)rpid, n, rp_hash) != ST_OK) return ST_OTHER;
        } else if (perms & (PERM_MC | PERM_GA)) {
            return ST_MISSING;   /* mc and ga are always bound to an RP ID */
        }
    }
    if ((st = pin_attempt_allowed()) != ST_OK) return st;
    if ((st = cp_shared(m, proto, ss)) != ST_OK) goto out;
    if ((st = pin_verify_hash(proto, ss, ph, ph_len)) != ST_OK) goto out;

    token_stop();
    cm_clear();
    cred_rng(s_tok.key, sizeof(s_tok.key));
    s_tok.in_use = true;
    s_tok.perms = (uint8_t)perms;
    s_tok.has_rp = sub == 0x09 && has_rp;
    if (s_tok.has_rp) memcpy(s_tok.rp_hash, rp_hash, 32);
    s_tok.start_us = s_tok.last_us = esp_timer_get_time();
    if (!pp_encrypt(proto, ss, s_tok.key, sizeof(s_tok.key), out, &out_len)) {
        token_stop();
        st = ST_OTHER;
        goto out;
    }
    CborEncoder map;
    cbor_encoder_create_map(&r->enc, &map, 1);
    cbor_encode_int(&map, 2);
    cbor_encode_byte_string(&map, out, out_len);
    cbor_encoder_close_container(&r->enc, &map);
    st = ST_OK;
out:
    mbedtls_platform_zeroize(ss, sizeof(ss));
    mbedtls_platform_zeroize(out, sizeof(out));
    return st;
}

static uint8_t cmd_client_pin(const CborValue *m, resp_t *r)
{
    CborValue v;
    int64_t sub = 0, proto = 0;
    if (!mfind(m, 2, NULL, &v)) return ST_MISSING;
    if (!get_uint(&v, &sub)) return ST_CBOR_TYPE;
    if (sub != 0x01 && sub != 0x02 && sub != 0x03 && sub != 0x04 && sub != 0x05 && sub != 0x09) {
        return ST_INVALID_SUBCMD;   /* 0x06/0x07: no built-in UV */
    }
    if (!mfind(m, 1, NULL, &v)) {
        if (sub != 0x01) return ST_MISSING;   /* getPINRetries needs no protocol */
    } else {
        if (!get_uint(&v, &proto)) return ST_CBOR_TYPE;
        if (proto != 1 && proto != 2) return ST_INVALID_PAR;
    }
    CborEncoder map;
    switch (sub) {
    case 0x01:
        cbor_encoder_create_map(&r->enc, &map, 2);
        cbor_encode_int(&map, 3);
        cbor_encode_int(&map, s_pin.retries);
        cbor_encode_int(&map, 4);
        cbor_encode_boolean(&map, s_consec >= PIN_MAX_CONSEC);   /* powerCycleState */
        cbor_encoder_close_container(&r->enc, &map);
        return ST_OK;
    case 0x02: {
        uint8_t pub[65];
        if (cred_ka_public((int)proto, pub) != ESP_OK) return ST_OTHER;
        cbor_encoder_create_map(&r->enc, &map, 1);
        cbor_encode_int(&map, 1);
        cose_key_enc(&map, pub, -25);
        cbor_encoder_close_container(&r->enc, &map);
        return ST_OK;
    }
    case 0x03:
        return cp_set_pin(m, (uint8_t)proto);
    case 0x04:
        return cp_change_pin(m, (uint8_t)proto);
    default:
        return cp_get_token(m, (uint8_t)proto, sub, r);
    }
}

/* pinUvAuthParam of makeCredential / getAssertion. */
typedef struct {
    bool present;
    uint8_t proto;
    uint8_t param[32];
    size_t len;
} puv_t;

/* Steps 1-2 of makeCredential and getAssertion: a zero-length pinUvAuthParam is a platform asking for a
 * touch (answered after the touch with PIN_NOT_SET / PIN_INVALID); otherwise the protocol must be valid. */
static uint8_t puv_parse(const CborValue *m, int64_t kparam, int64_t kproto, puv_t *p, bool *done)
{
    CborValue v;
    size_t n = 0;
    int64_t proto = 0;
    memset(p, 0, sizeof(*p));
    *done = false;
    if (!mfind(m, kparam, NULL, &v)) return ST_OK;
    if (!cbor_value_is_byte_string(&v)) return ST_CBOR_TYPE;
    if (cbor_value_get_string_length(&v, &n) != CborNoError) return ST_CBOR;
    if (n == 0) {
        *done = true;
        uint8_t up = fido_user_presence();
        if (up) return up;
        return s_pin.set ? ST_PIN_INVALID : ST_PIN_NOT_SET;
    }
    if (n <= sizeof(p->param) && !get_bytes(&v, p->param, sizeof(p->param), &p->len)) return ST_CBOR;
    if (!mfind(m, kproto, NULL, &v)) return ST_MISSING;
    if (!get_uint(&v, &proto)) return ST_CBOR_TYPE;
    if (proto != 1 && proto != 2) return ST_INVALID_PAR;
    p->present = true;
    p->proto = (uint8_t)proto;
    return ST_OK;
}

/* Step 11.1 / 6.1: pinUvAuthParam over clientDataHash with the token, the permission, the RP ID binding. */
static uint8_t puv_check(const puv_t *p, const uint8_t cdh[32], uint8_t perm, const uint8_t rp_hash[32])
{
    if (!s_pin.set) return ST_PIN_NOT_SET;
    if (!token_live() || !pp_verify(p->proto, s_tok.key, cdh, 32, p->param, p->len) || !(s_tok.perms & perm) ||
        (s_tok.has_rp && memcmp(s_tok.rp_hash, rp_hash, 32) != 0)) {
        return ST_PIN_AUTH_INVALID;
    }
    if (!s_tok.has_rp) {
        s_tok.has_rp = true;
        memcpy(s_tok.rp_hash, rp_hash, 32);
    }
    s_tok.last_us = esp_timer_get_time();
    return ST_OK;
}

/* credProtect (2.1 §12.1): level 3 needs UV, level 2 needs UV or an allowList (or excludeList). */
static bool cp_allowed(uint8_t level, bool uv, bool listed)
{
    return level == 3 ? uv : level == 2 ? (uv || listed) : true;
}

typedef struct {
    uint8_t id[FIDO_CRED_ID_LEN];
    bool found;
    bool uv;
} pick_t;

/* First listed credential that its credProtect level lets through. */
static bool pick_first(const uint8_t id[FIDO_CRED_ID_LEN], void *ctx)
{
    pick_t *p = ctx;
    if (!cp_allowed(cred_id_protect(id), p->uv, true)) return false;
    memcpy(p->id, id, FIDO_CRED_ID_LEN);
    p->found = true;
    return true;
}

/* user entity: id, and name/displayName only after UV (2.1 §6.2.2). Keys in canonical order. */
static void enc_user(CborEncoder *parent, const fido_resident_t *rec, bool uv)
{
    CborEncoder u;
    bool name = uv && rec->user_name_len, disp = uv && rec->display_len;
    cbor_encoder_create_map(parent, &u, 1 + name + disp);
    cbor_encode_text_stringz(&u, "id");
    cbor_encode_byte_string(&u, rec->user_id, rec->user_id_len);
    if (name) {
        cbor_encode_text_stringz(&u, "name");
        cbor_encode_text_string(&u, rec->user_name, rec->user_name_len);
    }
    if (disp) {
        cbor_encode_text_stringz(&u, "displayName");
        cbor_encode_text_string(&u, rec->display, rec->display_len);
    }
    cbor_encoder_close_container(parent, &u);
}


/* ---- makeCredential (0x01) ---- */

typedef struct {
    bool uv;
    bool hit;
} excl_t;

/* excludeList match. A credProtect level 3 credential is not revealed without UV (2.1 §6.1.2 step 12). */
static bool excl_fn(const uint8_t id[FIDO_CRED_ID_LEN], void *ctx)
{
    excl_t *e = ctx;
    if (cred_id_protect(id) == 3 && !e->uv) return false;
    e->hit = true;
    return true;
}

/* After a request that used the token and collected UP (2.1 §6.1.2 step 14, §6.2.2): the token keeps
 * only the lbw permission, which this authenticator never grants, so it cannot sign again. */
static void token_consumed(void)
{
    s_tok.perms = 0;
}

static uint8_t cmd_make_credential(const CborValue *m, resp_t *r)
{
    puv_t puv;
    bool done;
    uint8_t st = puv_parse(m, 8, 9, &puv, &done);
    if (done || st != ST_OK) return st;

    uint8_t cdh[32];
    if ((st = need_bytes(m, 1, cdh, 32)) != ST_OK) return st;

    /* rp: map with text id */
    CborValue rp, idv, user, v;
    if (!mfind(m, 2, NULL, &rp)) return ST_MISSING;
    if (!cbor_value_is_map(&rp) || !mfind(&rp, 0, "id", &idv) || !cbor_value_is_text_string(&idv)) {
        return ST_CBOR_TYPE;
    }
    char rpid[256];
    size_t rpid_len = 0;
    if (!get_text(&idv, rpid, sizeof(rpid), &rpid_len) || rpid_len == 0) return ST_INVALID_PAR;
    uint8_t rp_hash[32];
    if (sha_rp((const uint8_t *)rpid, rpid_len, rp_hash) != ST_OK) return ST_OTHER;

    /* user: map with byte id <= 64; name/displayName optional text */
    static fido_resident_t rec;   /* fido task only; too big for the stack next to the rest */
    memset(&rec, 0, sizeof(rec));
    if (!mfind(m, 3, NULL, &user)) return ST_MISSING;
    CborValue uid;
    if (!cbor_value_is_map(&user) || !mfind(&user, 0, "id", &uid) || !cbor_value_is_byte_string(&uid)) {
        return ST_CBOR_TYPE;
    }
    size_t uid_len = 0;
    if (!get_bytes(&uid, rec.user_id, sizeof(rec.user_id), &uid_len)) return ST_INVALID_PAR;
    rec.user_id_len = (uint8_t)uid_len;
    if ((st = opt_text(&user, "name", rec.user_name, sizeof(rec.user_name), &rec.user_name_len)) != ST_OK) return st;
    if ((st = opt_text(&user, "displayName", rec.display, sizeof(rec.display), &rec.display_len)) != ST_OK) return st;

    /* pubKeyCredParams: every element must be {type: text, alg: int}; ES256 must be among them. */
    bool es256 = false;
    if (!mfind(m, 4, NULL, &v)) return ST_MISSING;
    if (!cbor_value_is_array(&v)) return ST_CBOR_TYPE;
    CborValue it;
    if (cbor_value_enter_container(&v, &it) != CborNoError) return ST_CBOR;
    while (!cbor_value_at_end(&it)) {
        CborValue e = it, alg, type;
        if (cbor_value_advance(&it) != CborNoError) return ST_CBOR;
        int64_t a = 0;
        if (!cbor_value_is_map(&e) || !mfind(&e, 0, "alg", &alg) || !cbor_value_is_integer(&alg) ||
            !mfind(&e, 0, "type", &type) || !cbor_value_is_text_string(&type)) {
            return ST_CBOR_TYPE;
        }
        bool pk = false;
        cbor_value_text_string_equals(&type, "public-key", &pk);
        if (pk && cbor_value_get_int64(&alg, &a) == CborNoError && a == -7) es256 = true;
    }
    if (!es256) return ST_UNSUPPORTED_ALG;

    int o_up, o_uv, o_rk;
    if ((st = get_opts(m, 7, &o_up, &o_uv, &o_rk)) != ST_OK) return st;
    if (o_uv == 1 && !puv.present) return ST_INVALID_OPTION;   /* no built-in UV (step 5) */
    if (o_up == 0) return ST_INVALID_OPTION;
    bool want_rk = o_rk == 1;

    /* extensions: hmac-secret and credProtect are acted on; others are ignored. */
    bool want_hs = false;
    int64_t protect = 0;
    if (mfind(m, 6, NULL, &v)) {
        CborValue ev;
        if (!cbor_value_is_map(&v)) return ST_CBOR_TYPE;
        if (mfind(&v, 0, "hmac-secret", &ev) && !get_bool(&ev, &want_hs)) return ST_CBOR_TYPE;
        if (mfind(&v, 0, "credProtect", &ev) && !get_uint(&ev, &protect)) return ST_CBOR_TYPE;
        if (protect < 1 || protect > 3) protect = 0;   /* unknown level: extension ignored */
    }

    /* Step 7 (makeCredUvNotRqd): with a PIN set, only a discoverable credential needs pinUvAuthParam. */
    if (s_pin.set && !puv.present && want_rk) return ST_PUAT_REQUIRED;

    bool uv = false;
    if (puv.present) {
        if ((st = puv_check(&puv, cdh, PERM_MC, rp_hash)) != ST_OK) return st;
        uv = true;
    }

    /* excludeList: a credential of ours already on this rp means refuse (after touch). */
    if (mfind(m, 5, NULL, &v)) {
        excl_t ex = {.uv = uv};
        size_t cnt;
        if ((st = walk_desc(&v, rp_hash, excl_fn, &ex, &cnt)) != ST_OK) return st;
        if (ex.hit) {
            uint8_t up = fido_user_presence();
            return up ? up : ST_CRED_EXCLUDED;
        }
    }

    uint8_t up = fido_user_presence();
    if (up) return up;
    if (puv.present) token_consumed();

    uint8_t level = protect ? (uint8_t)protect : 1;
    uint8_t pub[65];
    if (cred_new_id(rp_hash, level, rec.cred_id) != ESP_OK) return ST_OTHER;
    if (cred_public_key(rp_hash, rec.cred_id, pub) != ESP_OK) return ST_OTHER;

    if (want_rk) {
        rec.cred_protect = level;
        memcpy(rec.rp_hash, rp_hash, 32);
        rec.rp_id_len = store_rpid(rpid, rpid_len, rec.rp_id);
        esp_err_t err = store_resident_put(&rec, NULL);
        if (err == ESP_ERR_NO_MEM || err == ESP_ERR_NVS_NOT_ENOUGH_SPACE) return ST_KEY_STORE_FULL;
        if (err != ESP_OK) return ST_OTHER;
    }

    /* authenticatorData: rpIdHash | flags | signCount 0 | aaguid | credIdLen | credId | COSE key | ext */
    bool ext = want_hs || protect;
    size_t off = 0;
    memcpy(s_authdata + off, rp_hash, 32); off += 32;
    s_authdata[off++] = 0x41 | (uv ? 0x04 : 0) | (ext ? 0x80 : 0);   /* UP | AT, UV, ED */
    memset(s_authdata + off, 0, 4); off += 4;
    memcpy(s_authdata + off, k_aaguid, 16); off += 16;
    s_authdata[off++] = 0x00;
    s_authdata[off++] = FIDO_CRED_ID_LEN;
    memcpy(s_authdata + off, rec.cred_id, FIDO_CRED_ID_LEN); off += FIDO_CRED_ID_LEN;
    size_t klen = cose_key(pub, s_cose, sizeof(s_cose));
    if (off + klen > sizeof(s_authdata)) return ST_OTHER;
    memcpy(s_authdata + off, s_cose, klen); off += klen;
    if (ext) {
        CborEncoder e, em;
        cbor_encoder_init(&e, s_authdata + off, sizeof(s_authdata) - off, 0);
        cbor_encoder_create_map(&e, &em, (size_t)(want_hs + (protect != 0)));
        if (protect) {   /* canonical order: "credProtect" < "hmac-secret" */
            cbor_encode_text_stringz(&em, "credProtect");
            cbor_encode_uint(&em, level);
        }
        if (want_hs) {
            /* CredRandom is derived from the credential id, so it always exists: answer true. */
            cbor_encode_text_stringz(&em, "hmac-secret");
            cbor_encode_boolean(&em, true);
        }
        cbor_encoder_close_container(&e, &em);
        if (cbor_encoder_get_extra_bytes_needed(&e) != 0) return ST_OTHER;
        off += cbor_encoder_get_buffer_size(&e, s_authdata + off);
    }

    /* Packed self attestation (WebAuthn L2 §8.2): signed with the credential key itself, no x5c. */
    uint8_t signed_buf[sizeof(s_authdata) + 32];
    memcpy(signed_buf, s_authdata, off);
    memcpy(signed_buf + off, cdh, 32);
    uint8_t raw[64], der[72];
    if (cred_sign(rp_hash, rec.cred_id, signed_buf, off + 32, raw) != ESP_OK) return ST_OTHER;
    size_t dlen = cred_raw_to_der(raw, der);

    CborEncoder map, stmt;
    cbor_encoder_create_map(&r->enc, &map, 3);
    cbor_encode_int(&map, 1);
    cbor_encode_text_stringz(&map, "packed");
    cbor_encode_int(&map, 2);
    cbor_encode_byte_string(&map, s_authdata, off);
    cbor_encode_int(&map, 3);
    cbor_encoder_create_map(&map, &stmt, 2);
    cbor_encode_text_stringz(&stmt, "alg");
    cbor_encode_int(&stmt, -7);
    cbor_encode_text_stringz(&stmt, "sig");
    cbor_encode_byte_string(&stmt, der, dlen);
    cbor_encoder_close_container(&map, &stmt);
    cbor_encoder_close_container(&r->enc, &map);
    return ST_OK;
}

/* ---- getAssertion (0x02), getNextAssertion (0x08), reset (0x07) ---- */

#define NEXT_TIMEOUT_US 30000000LL   /* pending getNextAssertion list expires after 30 s without a step */
#define RESET_WINDOW_US 10000000LL   /* reset is allowed only this long after power-up */

/* Remaining resident matches from a getAssertion, bound to one channel. */
typedef struct {
    bool active;
    bool up;                            /* UP was collected for the original request */
    bool uv;                            /* the request carried a valid pinUvAuthParam */
    uint32_t cid;
    uint8_t rp_hash[32];
    uint8_t cdh[32];
    uint8_t slots[FIDO_MAX_RESIDENT];   /* newest first; slots[next..count) are still owed */
    uint8_t count;
    uint8_t next;
    int64_t deadline_us;
    hs_t hs;                            /* hmac-secret inputs for the remaining credentials */
} pending_t;
static pending_t s_pend;

/* Drops the pending list and wipes the hmac-secret shared secret and salts it may hold. */
static void pend_clear(void)
{
    mbedtls_platform_zeroize(&s_pend, sizeof(s_pend));
}

/* Writes the resident slots for rp_hash, newest first, into out. Returns how many. cp_uv >= 0 drops the
 * credentials whose credProtect level hides them (no allowList; uv as given); cp_uv < 0 keeps all. */
static uint8_t resident_slots(const uint8_t rp_hash[32], int cp_uv, uint8_t out[FIDO_MAX_RESIDENT])
{
    uint32_t created[FIDO_MAX_RESIDENT];
    uint8_t n = 0;
    static fido_resident_t rec;
    for (size_t i = 0; i < FIDO_MAX_RESIDENT; i++) {
        if (store_resident_load(i, &rec) != ESP_OK || memcmp(rec.rp_hash, rp_hash, 32) != 0) continue;
        if (cp_uv >= 0 && !cp_allowed(rec.cred_protect, cp_uv, false)) continue;
        size_t j = n;
        while (j > 0 && created[j - 1] < rec.created) {
            created[j] = created[j - 1];
            out[j] = out[j - 1];
            j--;
        }
        created[j] = rec.created;
        out[j] = (uint8_t)i;
        n++;
    }
    return n;
}

/* Signs one assertion for cred_id and encodes it. numcreds > 0 adds numberOfCredentials (getAssertion only).
 * up: presence was collected; only then is the counter advanced (no flash writes without a press). */
static uint8_t emit_assertion(resp_t *r, const uint8_t rp_hash[32], const uint8_t cdh[32],
                              const uint8_t cred_id[FIDO_CRED_ID_LEN], uint32_t numcreds, bool up, bool uv,
                              const hs_t *hs)
{
    uint8_t hs_enc[80];
    size_t hs_len = 0;
    if (hs->proto) {
        uint8_t st = hs_output(hs, rp_hash, cred_id, hs_enc, &hs_len);
        if (st != ST_OK) return st;
    }
    uint32_t ctr = 0;
    if (up) {
        if (store_next_counter(&ctr) != ESP_OK) return ST_OTHER;
    } else {
        ctr = store_counter_peek();
    }

    size_t off = 0;
    memcpy(s_authdata + off, rp_hash, 32); off += 32;
    s_authdata[off++] = (up ? 0x01 : 0) | (uv ? 0x04 : 0) | (hs->proto ? 0x80 : 0);   /* UP, UV, ED */
    s_authdata[off++] = (uint8_t)(ctr >> 24);
    s_authdata[off++] = (uint8_t)(ctr >> 16);
    s_authdata[off++] = (uint8_t)(ctr >> 8);
    s_authdata[off++] = (uint8_t)ctr;
    if (hs->proto) {
        CborEncoder e, em;
        cbor_encoder_init(&e, s_authdata + off, sizeof(s_authdata) - off, 0);
        cbor_encoder_create_map(&e, &em, 1);
        cbor_encode_text_stringz(&em, "hmac-secret");
        cbor_encode_byte_string(&em, hs_enc, hs_len);
        cbor_encoder_close_container(&e, &em);
        if (cbor_encoder_get_extra_bytes_needed(&e) != 0) return ST_OTHER;
        off += cbor_encoder_get_buffer_size(&e, s_authdata + off);
    }

    uint8_t signed_buf[sizeof(s_authdata) + 32];
    memcpy(signed_buf, s_authdata, off);
    memcpy(signed_buf + off, cdh, 32);
    uint8_t raw[64], der[72];
    if (cred_sign(rp_hash, cred_id, signed_buf, off + 32, raw) != ESP_OK) return ST_OTHER;
    size_t dlen = cred_raw_to_der(raw, der);

    static fido_resident_t found;
    bool has_user = false;
    for (size_t i = 0; i < FIDO_MAX_RESIDENT && !has_user; i++) {
        if (store_resident_load(i, &found) == ESP_OK && memcmp(found.cred_id, cred_id, FIDO_CRED_ID_LEN) == 0) {
            has_user = true;
        }
    }

    size_t entries = 3 + (has_user ? 1 : 0) + (numcreds > 0 ? 1 : 0);
    CborEncoder map, cred;
    cbor_encoder_create_map(&r->enc, &map, entries);
    cbor_encode_int(&map, 1);
    cbor_encoder_create_map(&map, &cred, 2);
    cbor_encode_text_stringz(&cred, "id");
    cbor_encode_byte_string(&cred, cred_id, FIDO_CRED_ID_LEN);
    cbor_encode_text_stringz(&cred, "type");
    cbor_encode_text_stringz(&cred, "public-key");
    cbor_encoder_close_container(&map, &cred);
    cbor_encode_int(&map, 2);
    cbor_encode_byte_string(&map, s_authdata, off);
    cbor_encode_int(&map, 3);
    cbor_encode_byte_string(&map, der, dlen);
    if (has_user) {
        cbor_encode_int(&map, 4);
        enc_user(&map, &found, uv);
    }
    if (numcreds > 0) {
        cbor_encode_int(&map, 5);
        cbor_encode_int(&map, numcreds);
    }
    cbor_encoder_close_container(&r->enc, &map);
    return ST_OK;
}

static uint8_t cmd_get_assertion(uint32_t cid, const CborValue *m, resp_t *r)
{
    puv_t puv;
    bool done;
    uint8_t st = puv_parse(m, 6, 7, &puv, &done);
    if (done || st != ST_OK) return st;

    char rpid[256];
    size_t n = 0;
    CborValue v;
    if (!mfind(m, 1, NULL, &v)) return ST_MISSING;
    if (!cbor_value_is_text_string(&v)) return ST_CBOR_TYPE;
    if (!get_text(&v, rpid, sizeof(rpid), &n) || n == 0) return ST_INVALID_PAR;
    uint8_t rp_hash[32];
    if (sha_rp((const uint8_t *)rpid, n, rp_hash) != ST_OK) return ST_OTHER;

    uint8_t cdh[32];
    if ((st = need_bytes(m, 2, cdh, 32)) != ST_OK) return st;

    int o_up, o_uv, o_rk;
    if ((st = get_opts(m, 5, &o_up, &o_uv, &o_rk)) != ST_OK) return st;
    if (o_rk != -1) return ST_UNSUPPORTED_OPTION;              /* 2.1 §6.2.2 step 5 */
    if (o_uv == 1 && !puv.present) return ST_INVALID_OPTION;   /* no built-in UV */
    bool want_up = o_up != 0;

    /* hmac-secret: shape checked now; ECDH, saltAuth and decrypt after the presence check (spec order). */
    hs_req_t hq;
    if ((st = hs_parse(m, &hq)) != ST_OK) return st;
    if (hq.proto && !want_up) return ST_UNSUPPORTED_OPTION;   /* 2.1 §12.5 */

    /* Step 6: pinUvAuthParam before the credential search. */
    bool uv = false;
    if (puv.present) {
        if ((st = puv_check(&puv, cdh, PERM_GA, rp_hash)) != ST_OK) return st;
        uv = true;
    }

    /* Applicable credentials (2.1 §6.2.2 step 7): a non-empty allowList restricts the search to it; only
     * without one are discoverable credentials used. credProtect filters both. No match: NO_CREDENTIALS,
     * before any presence check. */
    pick_t pk = {.uv = uv};
    bool allow = false;
    uint8_t slots[FIDO_MAX_RESIDENT];
    uint8_t count = 0;
    if (mfind(m, 3, NULL, &v)) {
        size_t cnt = 0;
        if ((st = walk_desc(&v, rp_hash, pick_first, &pk, &cnt)) != ST_OK) return st;
        allow = cnt > 0;
    }
    if (!allow) {
        count = resident_slots(rp_hash, uv, slots);
        static fido_resident_t rec;
        if (count > 0 && store_resident_load(slots[0], &rec) == ESP_OK) {
            memcpy(pk.id, rec.cred_id, FIDO_CRED_ID_LEN);
            pk.found = true;
        }
    }
    if (!pk.found) return ST_NO_CREDENTIALS;

    if (want_up) {
        uint8_t up = fido_user_presence();
        if (up) return up;
        if (puv.present) token_consumed();
    }

    hs_t hs = {0};
    if (hq.proto) st = hs_open(&hq, &hs);
    hs.uv = uv;   /* CredRandomWithUV vs CredRandomWithoutUV */
    uint32_t numcreds = (!allow && count > 1) ? count : 0;
    if (st == ST_OK) st = emit_assertion(r, rp_hash, cdh, pk.id, numcreds, want_up, uv, &hs);

    pend_clear();
    if (st == ST_OK && numcreds > 0) {
        s_pend.active = true;
        s_pend.up = want_up;
        s_pend.uv = uv;
        s_pend.hs = hs;
        s_pend.cid = cid;
        memcpy(s_pend.rp_hash, rp_hash, 32);
        memcpy(s_pend.cdh, cdh, 32);
        memcpy(s_pend.slots, slots, count);
        s_pend.count = count;
        s_pend.next = 1;                       /* slot 0 was just returned */
        s_pend.deadline_us = esp_timer_get_time() + NEXT_TIMEOUT_US;
    }
    mbedtls_platform_zeroize(&hs, sizeof(hs));
    return st;
}

static uint8_t cmd_get_next_assertion(uint32_t cid, resp_t *r)
{
    int64_t now = esp_timer_get_time();
    if (!s_pend.active || s_pend.cid != cid || now > s_pend.deadline_us || s_pend.next >= s_pend.count) {
        pend_clear();
        return ST_NOT_ALLOWED;
    }
    static fido_resident_t rec;
    if (store_resident_load(s_pend.slots[s_pend.next], &rec) != ESP_OK ||
        memcmp(rec.rp_hash, s_pend.rp_hash, 32) != 0) {
        pend_clear();                /* list went stale, for example after an admin reset */
        return ST_NO_CREDENTIALS;
    }
    s_pend.next++;
    s_pend.deadline_us = now + NEXT_TIMEOUT_US;
    uint8_t st = emit_assertion(r, s_pend.rp_hash, s_pend.cdh, rec.cred_id, 0, s_pend.up, s_pend.uv, &s_pend.hs);
    if (st != ST_OK || s_pend.next >= s_pend.count) pend_clear();
    return st;
}

/* ---- credentialManagement (0x0A, 2.1 §6.8) ---- */

typedef struct {
    uint8_t kind;                       /* 0 none, 1 RPs, 2 credentials */
    uint8_t slots[FIDO_MAX_RESIDENT];
    uint8_t count;
    uint8_t next;
} cm_pend_t;
static cm_pend_t s_cm;

static void cm_clear(void)
{
    memset(&s_cm, 0, sizeof(s_cm));
}

/* Finds the resident slot holding the descriptor's credential id. */
static int cm_find(const CborValue *desc, fido_resident_t *rec)
{
    CborValue idv;
    uint8_t id[64];
    size_t n = 0;
    if (!cbor_value_is_map(desc) || !mfind(desc, 0, "id", &idv) || !cbor_value_is_byte_string(&idv)) return -2;
    if (!get_bytes(&idv, id, sizeof(id), &n) || n != FIDO_CRED_ID_LEN) return -1;
    for (int i = 0; i < FIDO_MAX_RESIDENT; i++) {
        if (store_resident_load(i, rec) == ESP_OK && cred_ct_equal(rec->cred_id, id, FIDO_CRED_ID_LEN)) return i;
    }
    return -1;
}

static void cm_rp(CborEncoder *map, const fido_resident_t *rec, uint32_t total)
{
    CborEncoder rp;
    cbor_encode_int(map, 3);
    cbor_encoder_create_map(map, &rp, 1);
    cbor_encode_text_stringz(&rp, "id");
    cbor_encode_text_string(&rp, rec->rp_id, rec->rp_id_len);
    cbor_encoder_close_container(map, &rp);
    cbor_encode_int(map, 4);
    cbor_encode_byte_string(map, rec->rp_hash, 32);
    if (total) {
        cbor_encode_int(map, 5);
        cbor_encode_uint(map, total);
    }
}

static uint8_t cm_cred(CborEncoder *map, const fido_resident_t *rec, uint32_t total)
{
    uint8_t pub[65];
    CborEncoder d;
    if (cred_public_key(rec->rp_hash, rec->cred_id, pub) != ESP_OK) return ST_OTHER;
    cbor_encode_int(map, 6);
    enc_user(map, rec, true);
    cbor_encode_int(map, 7);
    cbor_encoder_create_map(map, &d, 2);
    cbor_encode_text_stringz(&d, "id");
    cbor_encode_byte_string(&d, rec->cred_id, FIDO_CRED_ID_LEN);
    cbor_encode_text_stringz(&d, "type");
    cbor_encode_text_stringz(&d, "public-key");
    cbor_encoder_close_container(map, &d);
    cbor_encode_int(map, 8);
    cose_key_enc(map, pub, -7);
    if (total) {
        cbor_encode_int(map, 9);
        cbor_encode_uint(map, total);
    }
    cbor_encode_int(map, 10);
    cbor_encode_uint(map, rec->cred_protect);
    return ST_OK;
}

static uint8_t cmd_cred_mgmt(const CborValue *m, resp_t *r)
{
    CborValue v, params;
    int64_t sub = 0;
    uint8_t st;
    static fido_resident_t rec;
    if (!mfind(m, 1, NULL, &v)) return ST_MISSING;
    if (!get_uint(&v, &sub)) return ST_CBOR_TYPE;
    if (sub < 0x01 || sub > 0x07) return ST_INVALID_SUBCMD;
    bool has_params = mfind(m, 2, NULL, &params);
    if (has_params && !cbor_value_is_map(&params)) return ST_CBOR_TYPE;

    if (sub != 0x03 && sub != 0x05) {
        /* pinUvAuthParam = authenticate(token, subCommand || subCommandParams) */
        uint8_t msg[1 + 512];
        size_t mlen = 1;
        msg[0] = (uint8_t)sub;
        if (has_params) {
            CborValue end = params;
            const uint8_t *p0 = cbor_value_get_next_byte(&params);
            if (cbor_value_advance(&end) != CborNoError) return ST_CBOR;
            size_t pl = (size_t)(cbor_value_get_next_byte(&end) - p0);
            if (pl > sizeof(msg) - 1) return ST_INVALID_LEN;
            memcpy(msg + 1, p0, pl);
            mlen += pl;
        }
        uint8_t param[32];
        size_t plen = 0;
        int64_t proto = 0;
        if (!mfind(m, 4, NULL, &v)) return ST_PUAT_REQUIRED;
        if (!cbor_value_is_byte_string(&v)) return ST_CBOR_TYPE;
        if (!get_bytes(&v, param, sizeof(param), &plen)) plen = 0;
        if (!mfind(m, 3, NULL, &v)) return ST_MISSING;
        if (!get_uint(&v, &proto)) return ST_CBOR_TYPE;
        if (proto != 1 && proto != 2) return ST_INVALID_PAR;
        if (!token_live() || !pp_verify((uint8_t)proto, s_tok.key, msg, mlen, param, plen) ||
            !(s_tok.perms & PERM_CM)) {
            return ST_PIN_AUTH_INVALID;
        }
        /* Enumerating every RP needs a token without an RP ID (2.1 §6.8.2, §6.8.3). */
        if ((sub == 0x01 || sub == 0x02) && s_tok.has_rp) return ST_PIN_AUTH_INVALID;
        s_tok.last_us = esp_timer_get_time();
    }

    CborEncoder map;
    switch (sub) {
    case 0x01: {   /* getCredsMetadata */
        uint32_t n = store_resident_count();
        cbor_encoder_create_map(&r->enc, &map, 2);
        cbor_encode_int(&map, 1);
        cbor_encode_uint(&map, n);
        cbor_encode_int(&map, 2);
        cbor_encode_uint(&map, FIDO_MAX_RESIDENT - n);
        cbor_encoder_close_container(&r->enc, &map);
        return ST_OK;
    }
    case 0x02: {   /* enumerateRPsBegin: one slot per distinct rpIdHash */
        static fido_resident_t other;
        cm_clear();
        for (int i = 0; i < FIDO_MAX_RESIDENT; i++) {
            if (store_resident_load(i, &rec) != ESP_OK) continue;
            bool dup = false;
            for (int j = 0; j < s_cm.count && !dup; j++) {
                dup = store_resident_load(s_cm.slots[j], &other) == ESP_OK && !memcmp(other.rp_hash, rec.rp_hash, 32);
            }
            if (!dup) s_cm.slots[s_cm.count++] = (uint8_t)i;
        }
        if (s_cm.count == 0 || store_resident_load(s_cm.slots[0], &rec) != ESP_OK) return ST_NO_CREDENTIALS;
        s_cm.kind = 1;
        s_cm.next = 1;
        cbor_encoder_create_map(&r->enc, &map, 3);
        cm_rp(&map, &rec, s_cm.count);
        cbor_encoder_close_container(&r->enc, &map);
        return ST_OK;
    }
    case 0x04: {   /* enumerateCredentialsBegin {1: rpIdHash} */
        uint8_t rp_hash[32];
        if (!has_params) return ST_MISSING;
        if ((st = need_bytes(&params, 1, rp_hash, 32)) != ST_OK) return st;
        if (s_tok.has_rp && !cred_ct_equal(s_tok.rp_hash, rp_hash, 32)) return ST_PIN_AUTH_INVALID;
        cm_clear();
        s_cm.count = resident_slots(rp_hash, -1, s_cm.slots);
        if (s_cm.count == 0 || store_resident_load(s_cm.slots[0], &rec) != ESP_OK) {
            cm_clear();
            return ST_NO_CREDENTIALS;
        }
        s_cm.kind = 2;
        s_cm.next = 1;
        cbor_encoder_create_map(&r->enc, &map, 5);
        st = cm_cred(&map, &rec, s_cm.count);
        cbor_encoder_close_container(&r->enc, &map);
        return st;
    }
    case 0x03:
    case 0x05: {   /* enumerateRPsGetNextRP / enumerateCredentialsGetNextCredential */
        uint8_t kind = sub == 0x03 ? 1 : 2;
        if (!token_live() || s_cm.kind != kind || s_cm.next >= s_cm.count) {
            cm_clear();
            return ST_NOT_ALLOWED;
        }
        if (store_resident_load(s_cm.slots[s_cm.next++], &rec) != ESP_OK) {
            cm_clear();
            return ST_NO_CREDENTIALS;
        }
        cbor_encoder_create_map(&r->enc, &map, kind == 1 ? 2 : 4);
        st = ST_OK;
        if (kind == 1) cm_rp(&map, &rec, 0);
        else st = cm_cred(&map, &rec, 0);
        cbor_encoder_close_container(&r->enc, &map);
        if (s_cm.next >= s_cm.count) cm_clear();
        return st;
    }
    default: {     /* 0x06 deleteCredential {2: descriptor}, 0x07 updateUserInformation {2: descriptor, 3: user} */
        CborValue desc, user, uid;
        if (!has_params || !mfind(&params, 2, NULL, &desc)) return ST_MISSING;
        if (sub == 0x07 && !mfind(&params, 3, NULL, &user)) return ST_MISSING;
        int slot = cm_find(&desc, &rec);
        if (slot == -2) return ST_CBOR_TYPE;
        if (slot < 0) return ST_NO_CREDENTIALS;
        if (s_tok.has_rp && !cred_ct_equal(s_tok.rp_hash, rec.rp_hash, 32)) return ST_PIN_AUTH_INVALID;
        if (sub == 0x06) return store_resident_delete((size_t)slot) == ESP_OK ? ST_OK : ST_OTHER;
        if (!cbor_value_is_map(&user) || !mfind(&user, 0, "id", &uid) || !cbor_value_is_byte_string(&uid)) {
            return ST_CBOR_TYPE;
        }
        uint8_t id[FIDO_USER_MAX];
        size_t n = 0;
        if (!get_bytes(&uid, id, sizeof(id), &n) || n != rec.user_id_len || memcmp(id, rec.user_id, n) != 0) {
            return ST_INVALID_PAR;
        }
        /* Absent name/displayName are removed (2.1 §6.8.6). */
        if ((st = opt_text(&user, "name", rec.user_name, sizeof(rec.user_name), &rec.user_name_len)) != ST_OK) {
            return st;
        }
        if ((st = opt_text(&user, "displayName", rec.display, sizeof(rec.display), &rec.display_len)) != ST_OK) {
            return st;
        }
        return store_resident_put(&rec, NULL) == ESP_OK ? ST_OK : ST_OTHER;
    }
    }
}

/* ---- authenticatorSelection (0x0B) ---- */

static uint8_t cmd_selection(void)
{
    uint8_t up = fido_user_presence();
    return up ? up : ST_OK;
}

/* ---- reset, init, tick ---- */

static void pin_state_load(void)
{
    if (store_pin_load(&s_pin) != ESP_OK) {
        memset(&s_pin, 0, sizeof(s_pin));
        s_pin.set = true;   /* unreadable: blocked until reset rather than open */
    }
    s_pin_set_cache = s_pin.set;
    s_pin_retries_cache = s_pin.retries;
}

esp_err_t ctap2_reset_state(void)
{
    pend_clear();
    cm_clear();
    token_stop();
    s_consec = 0;
    esp_err_t err = store_reset();
    if (cred_ka_regen() != ESP_OK && err == ESP_OK) err = ESP_FAIL;   /* regenerate() the key-agreement keys */
    pin_state_load();
    return err;
}

/* The PIN record is keyed from the effective master, which harden changes: re-save it under the new keys. */
esp_err_t ctap2_harden(void)
{
    bool was = store_is_hardened();
    esp_err_t err = store_harden();
    /* Once the master changed, re-save even if erasing residents failed, or the PIN is blocked on boot. */
    if (!was && store_is_hardened()) {
        esp_err_t perr = pin_save();
        if (err == ESP_OK) err = perr;
    }
    return err;
}

/* Reset is refused after the window. The window is checked before the touch so a late request costs nothing. */
static uint8_t cmd_reset(void)
{
    if (esp_timer_get_time() > RESET_WINDOW_US) return ST_NOT_ALLOWED;
    uint8_t up = fido_user_presence();
    if (up) return up;
    return ctap2_reset_state() == ESP_OK ? ST_OK : ST_OTHER;
}

void ctap2_init(void)
{
    token_stop();
    s_consec = 0;
    pin_state_load();
}

void ctap2_tick(void)
{
    if (s_pend.active && esp_timer_get_time() > s_pend.deadline_us) pend_clear();
    token_live();   /* expires the token (and credentialManagement state) on time */
}

/* ---- dispatch ---- */

size_t ctap2_handle(uint32_t cid, const uint8_t *req, size_t len, uint8_t *out, size_t cap)
{
    if (len < 1 || cap < 2) { out[0] = ST_INVALID_LEN; return 1; }
    /* Only getNextAssertion may follow a getAssertion, and only credentialManagement its own enumeration. */
    if (req[0] != 0x08) pend_clear();
    if (req[0] != 0x0a) cm_clear();

    resp_t r;
    uint8_t st;
    switch (req[0]) {
    case 0x04:
        if (len != 1) { out[0] = ST_INVALID_LEN; return 1; }
        resp_begin(&r, out, cap);
        st = cmd_get_info(&r);
        break;
    case 0x07:
        out[0] = (len == 1) ? cmd_reset() : ST_INVALID_LEN;
        return 1;
    case 0x0b:
        out[0] = (len == 1) ? cmd_selection() : ST_INVALID_LEN;
        return 1;
    case 0x08:
        if (len != 1) { out[0] = ST_INVALID_LEN; return 1; }
        resp_begin(&r, out, cap);
        st = cmd_get_next_assertion(cid, &r);
        break;
    case 0x01:
    case 0x02:
    case 0x06:
    case 0x0a: {
        CborParser parser;
        CborValue root;
        /* Canonical-form, depth and size check first (iterative), so tinycbor's recursive walkers below
         * only ever see shallow, well-formed input. */
        if (!cbor_canonical_ok(req + 1, len - 1) ||
            cbor_parser_init(req + 1, len - 1, 0, &parser, &root) != CborNoError || !cbor_value_is_map(&root)) {
            out[0] = ST_CBOR;
            return 1;
        }
        resp_begin(&r, out, cap);
        st = (req[0] == 0x01)   ? cmd_make_credential(&root, &r)
             : (req[0] == 0x02) ? cmd_get_assertion(cid, &root, &r)
             : (req[0] == 0x06) ? cmd_client_pin(&root, &r)
                                : cmd_cred_mgmt(&root, &r);
        break;
    }
    default:
        out[0] = ST_INVALID_CMD;
        return 1;
    }
    if (st != ST_OK) {
        out[0] = st;
        return 1;
    }
    if (cbor_encoder_get_extra_bytes_needed(&r.enc) != 0) { out[0] = ST_OTHER; return 1; }
    ESP_LOGI(TAG, "cmd 0x%02x ok", req[0]);
    return resp_end(&r);
}
