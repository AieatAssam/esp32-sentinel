#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"

#define FIDO_CRED_ID_LEN   48   /* see cred.h */
#define FIDO_MAX_RESIDENT  16
#define FIDO_USER_MAX      64   /* user.id max (WebAuthn); name/displayName are truncated to this */
#define FIDO_RPID_MAX      128  /* longer rpIds are stored truncated (CTAP 2.1 §6.8.7), display only */

/* Resident (discoverable) credential record, NVS keys "c00".."c15". */
typedef struct {
    uint8_t ver;            /* FIDO_RES_VER */
    uint8_t cred_protect;   /* 1..3 */
    uint8_t rp_id_len;
    uint8_t user_id_len;
    uint8_t user_name_len;
    uint8_t display_len;
    uint8_t pad[2];
    uint32_t created;       /* set by store_resident_put(): increases with each credential */
    uint8_t rp_hash[32];
    uint8_t cred_id[FIDO_CRED_ID_LEN];
    char rp_id[FIDO_RPID_MAX];
    uint8_t user_id[FIDO_USER_MAX];
    char user_name[FIDO_USER_MAX];
    char display[FIDO_USER_MAX];
} fido_resident_t;
#define FIDO_RES_VER 2

/* Loads or creates the master secret and detects an HMAC eFuse key. Call once after nvs_flash_init(),
 * with a true entropy source on (see fido_init). Erases legacy-format resident records. */
esp_err_t store_init(void);
/* out = HMAC-SHA256(effective master, msg). Every credential key and secret derives from this. */
esp_err_t store_kdf(const uint8_t *msg, size_t len, uint8_t out[32]);
bool store_is_hardened(void);
/* Erases the master secret, all resident credentials, the PIN state and the counter, then makes a new master. */
esp_err_t store_reset(void);
/* Burns a random key into a free HMAC_UP key block. Irreversible: changes the effective master. */
esp_err_t store_harden(void);
/* Next value of the global signature counter (strictly increasing, also across power loss). NVS holds a
 * reserved ceiling and is written once every STORE_CTR_BATCH signatures. */
esp_err_t store_next_counter(uint32_t *ctr);
/* Last value handed out (0 before the first signature). */
uint32_t store_counter_peek(void);
uint32_t store_resident_count(void);
/* Stores a resident record. A record with the same rp_hash and user id is overwritten (CTAP 2.1 §6.1.2
 * step 18); otherwise the first free slot. ESP_ERR_NO_MEM when all slots are taken. *slot gets the index. */
esp_err_t store_resident_put(const fido_resident_t *rec, int *slot);
/* Loads slot idx (0..FIDO_MAX_RESIDENT-1). ESP_ERR_NOT_FOUND when the slot is empty. */
esp_err_t store_resident_load(size_t idx, fido_resident_t *out);
esp_err_t store_resident_delete(size_t idx);

/* ---- PIN state (clientPIN). Stored encrypted and MACed under keys derived from the master. ---- */
typedef struct {
    bool set;
    uint8_t retries;        /* 0..8 */
    uint8_t min_len;        /* minPINLength, code points */
    uint8_t hash[16];       /* LEFT(SHA-256(PIN), 16) */
} store_pin_t;
#define STORE_PIN_RETRIES 8
/* Loads the PIN state. A missing record reads as "not set, 8 retries". A record that fails its MAC reads
 * as set with 0 retries (blocked until reset). */
esp_err_t store_pin_load(store_pin_t *p);
/* Persists the PIN state and commits before returning. */
esp_err_t store_pin_save(const store_pin_t *p);
