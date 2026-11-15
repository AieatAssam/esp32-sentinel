#include <string.h>
#include "cred.h"
#include "fido_priv.h"
#include "store.h"
#include "u2f.h"

#define SW_NO_ERROR          0x9000
#define SW_CONDITIONS       0x6985
#define SW_WRONG_DATA       0x6a80
#define SW_WRONG_P1P2       0x6a86
#define SW_WRONG_LENGTH     0x6700
#define SW_CLA_NOT_SUPPORTED 0x6e00
#define SW_INS_NOT_SUPPORTED 0x6d00

#define INS_REGISTER     0x01
#define INS_AUTHENTICATE 0x02
#define INS_VERSION      0x03

#define P1_ENFORCE       0x03
#define P1_CHECK_ONLY    0x07
#define P1_DONT_ENFORCE  0x08


static size_t put_sw(uint8_t *out, size_t off, uint16_t sw)
{
    out[off] = (uint8_t)(sw >> 8);
    out[off + 1] = (uint8_t)sw;
    return off + 2;
}

static size_t sw_only(uint8_t *out, uint16_t sw)
{
    return put_sw(out, 0, sw);
}

/* Registration: challenge(32) || appId(32). Signature covers 0x00 || appId || challenge || keyHandle || pubkey.
 * The application parameter is used as the rpIdHash itself, so a U2F credential for appId SHA-256(rpId) is
 * the same credential over CTAP2 (CTAP 2.1 §10.4). P1 is not checked: U2F v1.2 sends 0x00, some hosts 0x03. */
static size_t do_register(const uint8_t *data, size_t lc, uint8_t *out, size_t cap)
{
    if (lc != 64) return sw_only(out, SW_WRONG_LENGTH);
    const uint8_t *challenge = data;
    const uint8_t *app = data + 32;

    if (!fido_u2f_presence()) return sw_only(out, SW_CONDITIONS);

    uint8_t kh[FIDO_CRED_ID_LEN];
    uint8_t pub[65];
    if (cred_new_id(app, 1, kh) != ESP_OK) return sw_only(out, SW_CONDITIONS);
    if (cred_public_key(app, kh, pub) != ESP_OK) return sw_only(out, SW_CONDITIONS);

    /* Signed data: 0x00 || appId || challenge || keyHandle || pubkey. */
    uint8_t tbs[1 + 32 + 32 + FIDO_CRED_ID_LEN + 65];
    size_t n = 0;
    tbs[n++] = 0x00;
    memcpy(tbs + n, app, 32); n += 32;
    memcpy(tbs + n, challenge, 32); n += 32;
    memcpy(tbs + n, kh, FIDO_CRED_ID_LEN); n += FIDO_CRED_ID_LEN;
    memcpy(tbs + n, pub, 65); n += 65;
    uint8_t raw[64], der[72];
    if (attest_sign(tbs, n, raw) != ESP_OK) return sw_only(out, SW_CONDITIONS);
    size_t dlen = cred_raw_to_der(raw, der);

    size_t clen = 0;
    const uint8_t *cert = attest_cert(&clen);

    /* Response: 0x05 || pubkey(65) || khLen || keyHandle || cert || sig || SW. */
    size_t need = 1 + 65 + 1 + FIDO_CRED_ID_LEN + clen + dlen + 2;
    if (need > cap) return sw_only(out, SW_WRONG_LENGTH);
    size_t o = 0;
    out[o++] = 0x05;
    memcpy(out + o, pub, 65); o += 65;
    out[o++] = FIDO_CRED_ID_LEN;
    memcpy(out + o, kh, FIDO_CRED_ID_LEN); o += FIDO_CRED_ID_LEN;
    memcpy(out + o, cert, clen); o += clen;
    memcpy(out + o, der, dlen); o += dlen;
    return put_sw(out, o, SW_NO_ERROR);
}

/* Authentication: challenge(32) || appId(32) || khLen(1) || keyHandle. Signs appId || flags || ctr || challenge. */
static size_t do_authenticate(const uint8_t *data, size_t lc, uint8_t p1, uint8_t *out, size_t cap)
{
    if (lc < 65) return sw_only(out, SW_WRONG_LENGTH);
    const uint8_t *challenge = data;
    const uint8_t *app = data + 32;
    size_t khl = data[64];
    if (khl != FIDO_CRED_ID_LEN) return sw_only(out, SW_WRONG_DATA);
    if (lc != 65 + khl) return sw_only(out, SW_WRONG_LENGTH);
    const uint8_t *kh = data + 65;
    if (p1 != P1_ENFORCE && p1 != P1_CHECK_ONLY && p1 != P1_DONT_ENFORCE) return sw_only(out, SW_WRONG_P1P2);

    const uint8_t *rp_hash = app;
    if (!cred_id_is_ours(rp_hash, kh, khl)) return sw_only(out, SW_WRONG_DATA);
    /* credProtect 3 (UV required) cannot be met over U2F: such a credential is "not ours" here. */
    if (cred_id_protect(kh) == 3) return sw_only(out, SW_WRONG_DATA);
    if (p1 == P1_CHECK_ONLY) return sw_only(out, SW_CONDITIONS);

    uint8_t flags = 0x00;
    uint32_t ctr = 0;
    if (p1 == P1_ENFORCE) {
        if (!fido_u2f_presence()) return sw_only(out, SW_CONDITIONS);
        flags = 0x01;
        if (store_next_counter(&ctr) != ESP_OK) return sw_only(out, SW_CONDITIONS);
    } else {
        /* Don't-enforce: no presence, so the counter is reported, not advanced (no flash write without a press). */
        ctr = store_counter_peek();
    }

    uint8_t tbs[32 + 1 + 4 + 32];
    size_t n = 0;
    memcpy(tbs + n, app, 32); n += 32;
    tbs[n++] = flags;
    tbs[n++] = (uint8_t)(ctr >> 24);
    tbs[n++] = (uint8_t)(ctr >> 16);
    tbs[n++] = (uint8_t)(ctr >> 8);
    tbs[n++] = (uint8_t)ctr;
    memcpy(tbs + n, challenge, 32); n += 32;
    uint8_t raw[64], der[72];
    if (cred_sign(rp_hash, kh, tbs, n, raw) != ESP_OK) return sw_only(out, SW_CONDITIONS);
    size_t dlen = cred_raw_to_der(raw, der);

    size_t need = 1 + 4 + dlen + 2;
    if (need > cap) return sw_only(out, SW_WRONG_LENGTH);
    size_t o = 0;
    out[o++] = flags;
    out[o++] = (uint8_t)(ctr >> 24);
    out[o++] = (uint8_t)(ctr >> 16);
    out[o++] = (uint8_t)(ctr >> 8);
    out[o++] = (uint8_t)ctr;
    memcpy(out + o, der, dlen); o += dlen;
    return put_sw(out, o, SW_NO_ERROR);
}

/* Parsed APDU body. Le is accepted and ignored: the whole response is always returned. */
typedef struct {
    uint8_t p1;
    size_t lc;
    const uint8_t *data;
} apdu_body_t;

/* Lc and data in short form (one Lc byte) or extended form (0x00 Lc1 Lc2), each optionally followed by Le.
 * Returns false when the total length does not match the declared Lc. */
static bool parse_body(const uint8_t *apdu, size_t len, apdu_body_t *b)
{
    size_t rest = len - 4;
    b->p1 = apdu[2];
    b->lc = 0;
    b->data = NULL;
    if (rest <= 1) return true;             /* case 1, or short Le only */
    if (apdu[4] == 0x00) {                  /* extended */
        if (rest < 3) return false;
        size_t lc = ((size_t)apdu[5] << 8) | apdu[6];
        if (rest != 3 + lc && rest != 5 + lc) return false;
        b->lc = lc;
        b->data = lc ? apdu + 7 : NULL;
        return true;
    }
    size_t lc = apdu[4];
    if (rest != 1 + lc && rest != 2 + lc) return false;
    b->lc = lc;
    b->data = lc ? apdu + 5 : NULL;
    return true;
}

size_t u2f_handle(const uint8_t *apdu, size_t len, uint8_t *out, size_t cap)
{
    if (len < 4) return sw_only(out, SW_WRONG_LENGTH);
    if (apdu[0] != 0x00) return sw_only(out, SW_CLA_NOT_SUPPORTED);
    uint8_t ins = apdu[1];
    if (ins != INS_REGISTER && ins != INS_AUTHENTICATE && ins != INS_VERSION) {
        return sw_only(out, SW_INS_NOT_SUPPORTED);
    }
    apdu_body_t b;
    if (!parse_body(apdu, len, &b)) return sw_only(out, SW_WRONG_LENGTH);

    switch (ins) {
    case INS_VERSION:
        if (b.lc != 0) return sw_only(out, SW_WRONG_LENGTH);
        if (cap < 8) return sw_only(out, SW_WRONG_LENGTH);
        memcpy(out, "U2F_V2", 6);
        return put_sw(out, 6, SW_NO_ERROR);
    case INS_REGISTER:
        return do_register(b.data, b.lc, out, cap);
    default:
        return do_authenticate(b.data, b.lc, b.p1, out, cap);
    }
}
