#include <string.h>
#include "esp_efuse.h"
#include "esp_hmac.h"
#include "esp_log.h"
#include "esp_random.h"
#include "nvs.h"
#include "mbedtls/platform_util.h"
#include "psa/crypto.h"
#include "cred.h"
#include "store.h"

static const char *TAG = "fido_store";
#define NS "fido"

static uint8_t s_master[32];
static bool s_hardened;
static esp_efuse_block_t s_hw_blk;
static uint32_t s_resident;
static bool s_ready;

/* True if the namespace holds any key besides "msec" (PIN, counter, residents), or cannot be listed. */
static bool other_keys_present(void)
{
    nvs_iterator_t it = NULL;
    bool other = false;
    esp_err_t e = nvs_entry_find(NVS_DEFAULT_PART_NAME, NS, NVS_TYPE_ANY, &it);
    while (e == ESP_OK && !other) {
        nvs_entry_info_t info;
        other = nvs_entry_info(it, &info) != ESP_OK || strcmp(info.key, "msec") != 0;
        if (!other) e = nvs_entry_next(&it);
    }
    nvs_release_iterator(it);
    return other || (e != ESP_OK && e != ESP_ERR_NVS_NOT_FOUND);
}

static esp_err_t load_master(void)
{
    nvs_handle_t h;
    esp_err_t err = nvs_open(NS, NVS_READWRITE, &h);
    if (err != ESP_OK) return err;
    size_t len = sizeof(s_master);
    err = nvs_get_blob(h, "msec", s_master, &len);
    if (err == ESP_ERR_NVS_NOT_FOUND || (err == ESP_OK && len != sizeof(s_master))) {
        /* A new master would orphan every existing credential and the PIN: only on an empty store. */
        if (other_keys_present()) {
            ESP_LOGE(TAG, "master secret missing or damaged but FIDO records exist; nothing written. "
                          "FIDO reset (BOOT press) then reboot recovers, deleting all passkeys.");
            nvs_close(h);
            return ESP_ERR_INVALID_STATE;
        }
        cred_rng(s_master, sizeof(s_master));
        err = nvs_set_blob(h, "msec", s_master, sizeof(s_master));
        if (err == ESP_OK) err = nvs_commit(h);
    }
    nvs_close(h);
    return err;
}

static void res_key(char key[8], size_t i)
{
    snprintf(key, 8, "c%02u", (unsigned)(i % 100));
}

static void count_resident(void)
{
    s_resident = 0;
    nvs_handle_t h;
    if (nvs_open(NS, NVS_READONLY, &h) != ESP_OK) return;
    for (size_t i = 0; i < FIDO_MAX_RESIDENT; i++) {
        char key[8];
        res_key(key, i);
        size_t len = 0;
        if (nvs_get_blob(h, key, NULL, &len) == ESP_OK) s_resident++;
    }
    nvs_close(h);
}

/* Records of the first format ("r00".."r15") hold credential ids that no longer verify: drop them. */
static void erase_legacy(void)
{
    nvs_handle_t h;
    if (nvs_open(NS, NVS_READWRITE, &h) != ESP_OK) return;
    bool any = false;
    for (size_t i = 0; i < FIDO_MAX_RESIDENT; i++) {
        char key[8];
        snprintf(key, sizeof(key), "r%02u", (unsigned)i);
        if (nvs_erase_key(h, key) == ESP_OK) any = true;
    }
    if (any) {
        nvs_commit(h);
        ESP_LOGW(TAG, "erased legacy resident records");
    }
    nvs_close(h);
}

/* Burned key block is found by purpose; its key id is block - EFUSE_BLK_KEY0. */
static void detect_hardware_key(void)
{
    s_hardened = esp_efuse_find_purpose(ESP_EFUSE_KEY_PURPOSE_HMAC_UP, &s_hw_blk);
}

esp_err_t store_init(void)
{
    esp_err_t err = load_master();
    if (err != ESP_OK) return err;
    detect_hardware_key();
    erase_legacy();
    count_resident();
    s_ready = true;
    ESP_LOGI(TAG, "ready, hardened=%d resident=%u", s_hardened, (unsigned)s_resident);
    return ESP_OK;
}

/* Effective master: the stored secret, or HMAC(hw key, secret) once hardened. */
static esp_err_t effective_master(uint8_t out[32])
{
    if (!s_hardened) {
        memcpy(out, s_master, 32);
        return ESP_OK;
    }
#if CONFIG_EFUSE_VIRTUAL
    /* Virtual eFuse: no HMAC peripheral in this build, compute the same HMAC in software. */
    uint8_t key[32];
    esp_err_t err = esp_efuse_read_block(s_hw_blk, key, 0, 256);
    if (err != ESP_OK) return err;
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attr, PSA_KEY_TYPE_HMAC);
    psa_set_key_bits(&attr, 256);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&attr, PSA_ALG_HMAC(PSA_ALG_SHA_256));
    mbedtls_svc_key_id_t kid = MBEDTLS_SVC_KEY_ID_INIT;
    if (psa_import_key(&attr, key, sizeof(key), &kid) != PSA_SUCCESS) return ESP_FAIL;
    size_t olen = 0;
    psa_status_t st = psa_mac_compute(kid, PSA_ALG_HMAC(PSA_ALG_SHA_256), s_master, sizeof(s_master),
                                      out, 32, &olen);
    psa_destroy_key(kid);
    mbedtls_platform_zeroize(key, sizeof(key));
    return st == PSA_SUCCESS ? ESP_OK : ESP_FAIL;
#else
    return esp_hmac_calculate((hmac_key_id_t)(s_hw_blk - EFUSE_BLK_KEY0), s_master, sizeof(s_master), out);
#endif
}

esp_err_t store_kdf(const uint8_t *msg, size_t len, uint8_t out[32])
{
    if (!s_ready || !msg || !out || len == 0 || len > 256) return ESP_ERR_INVALID_ARG;
    uint8_t m[32];
    esp_err_t err = effective_master(m);
    if (err != ESP_OK) return err;

    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attr, PSA_KEY_TYPE_HMAC);
    psa_set_key_bits(&attr, 256);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&attr, PSA_ALG_HMAC(PSA_ALG_SHA_256));
    mbedtls_svc_key_id_t kid = MBEDTLS_SVC_KEY_ID_INIT;
    psa_status_t st = psa_import_key(&attr, m, sizeof(m), &kid);
    mbedtls_platform_zeroize(m, sizeof(m));
    if (st != PSA_SUCCESS) return ESP_FAIL;
    size_t olen = 0;
    st = psa_mac_compute(kid, PSA_ALG_HMAC(PSA_ALG_SHA_256), msg, len, out, 32, &olen);
    psa_destroy_key(kid);
    return st == PSA_SUCCESS ? ESP_OK : ESP_FAIL;
}

bool store_is_hardened(void)
{
    return s_hardened;
}

static esp_err_t erase_residents(nvs_handle_t h)
{
    for (size_t i = 0; i < FIDO_MAX_RESIDENT; i++) {
        char key[8];
        res_key(key, i);
        esp_err_t err = nvs_erase_key(h, key);
        if (err != ESP_OK && err != ESP_ERR_NVS_NOT_FOUND) return err;
    }
    return ESP_OK;
}

esp_err_t store_reset(void)
{
    nvs_handle_t h;
    esp_err_t err = nvs_open(NS, NVS_READWRITE, &h);
    if (err != ESP_OK) return err;
    err = erase_residents(h);
    /* No counter exists until the first signature; a missing key is not a failure. */
    if (err == ESP_OK) {
        err = nvs_erase_key(h, "pin");
        if (err == ESP_ERR_NVS_NOT_FOUND) err = ESP_OK;
    }
    /* The counter is kept: all credentials die with the master, and a counter that only grows is never wrong. */
    if (err == ESP_OK) {
        cred_rng(s_master, sizeof(s_master));
        err = nvs_set_blob(h, "msec", s_master, sizeof(s_master));
    }
    if (err == ESP_OK) err = nvs_commit(h);
    nvs_close(h);
    if (err != ESP_OK) ESP_LOGE(TAG, "reset failed: %s", esp_err_to_name(err));
    s_resident = 0;
    return err;
}

esp_err_t store_harden(void)
{
    if (s_hardened || !s_ready) return ESP_ERR_INVALID_STATE;   /* never burn a key for a store that did not start */
    esp_efuse_block_t blk = EFUSE_BLK_KEY0;
    bool found = false;
    for (; blk <= EFUSE_BLK_KEY5; blk++) {
        if (esp_efuse_key_block_unused(blk)) { found = true; break; }
    }
    if (!found) return ESP_ERR_NOT_FOUND;

    uint8_t key[32];
    cred_rng(key, sizeof(key));
    /* Sets read/write protection and HMAC_UP purpose on this block only. */
    esp_err_t err = esp_efuse_write_key(blk, ESP_EFUSE_KEY_PURPOSE_HMAC_UP, key, sizeof(key));
    mbedtls_platform_zeroize(key, sizeof(key));
    if (err != ESP_OK) return err;

    s_hw_blk = blk;
    s_hardened = true;
    /* Old resident records can no longer be verified under the new master. */
    nvs_handle_t h;
    err = nvs_open(NS, NVS_READWRITE, &h);
    if (err == ESP_OK) {
        err = erase_residents(h);
        if (err == ESP_OK) err = nvs_commit(h);
        nvs_close(h);
    }
    count_resident();
    return err;
}

/* Counter batching: NVS "ctr" holds a ceiling C. Every value handed out is <= the ceiling committed before
 * it was handed out, and after boot counting resumes above the stored ceiling, so the counter never repeats
 * or goes backwards across power loss. Flash is written once per STORE_CTR_BATCH signatures. */
#define STORE_CTR_BATCH 16
static uint32_t s_ctr, s_ctr_ceiling;
static bool s_ctr_loaded;

static esp_err_t ctr_load(void)
{
    if (s_ctr_loaded) return ESP_OK;
    nvs_handle_t h;
    esp_err_t err = nvs_open(NS, NVS_READONLY, &h);
    uint32_t c = 0;
    if (err == ESP_OK) {
        err = nvs_get_u32(h, "ctr", &c);
        nvs_close(h);
    }
    if (err == ESP_ERR_NVS_NOT_FOUND) err = ESP_OK;
    if (err != ESP_OK) return err;
    s_ctr = s_ctr_ceiling = c;   /* resume above everything handed out before */
    s_ctr_loaded = true;
    return ESP_OK;
}

esp_err_t store_next_counter(uint32_t *ctr)
{
    nvs_handle_t h;
    esp_err_t err = ctr_load();
    if (err != ESP_OK) return err;
    if (s_ctr == UINT32_MAX) return ESP_ERR_INVALID_STATE;   /* would wrap: refuse to sign */
    uint32_t v = s_ctr + 1;
    if (v > s_ctr_ceiling) {
        uint32_t ceil = (UINT32_MAX - v < STORE_CTR_BATCH - 1) ? UINT32_MAX : v + STORE_CTR_BATCH - 1;
        err = nvs_open(NS, NVS_READWRITE, &h);
        if (err != ESP_OK) return err;
        err = nvs_set_u32(h, "ctr", ceil);
        if (err == ESP_OK) err = nvs_commit(h);
        nvs_close(h);
        if (err != ESP_OK) return err;
        s_ctr_ceiling = ceil;
    }
    s_ctr = v;
    *ctr = v;
    return ESP_OK;
}

uint32_t store_counter_peek(void)
{
    return ctr_load() == ESP_OK ? s_ctr : 0;
}

uint32_t store_resident_count(void)
{
    return s_resident;
}

static esp_err_t res_get(nvs_handle_t h, size_t i, fido_resident_t *out)
{
    char key[8];
    res_key(key, i);
    size_t len = sizeof(*out);
    esp_err_t e = nvs_get_blob(h, key, out, &len);
    if (e == ESP_OK && (len != sizeof(*out) || out->ver != FIDO_RES_VER)) e = ESP_ERR_INVALID_SIZE;
    return e;
}

esp_err_t store_resident_put(const fido_resident_t *rec, int *slot_out)
{
    if (!rec || !s_ready) return ESP_ERR_INVALID_ARG;
    nvs_handle_t h;
    esp_err_t err = nvs_open(NS, NVS_READWRITE, &h);
    if (err != ESP_OK) return err;
    fido_resident_t copy = *rec;
    uint32_t newest = 0;
    int free_slot = -1, same = -1;
    for (size_t i = 0; i < FIDO_MAX_RESIDENT; i++) {
        fido_resident_t old;
        esp_err_t e = res_get(h, i, &old);
        if (e == ESP_ERR_NVS_NOT_FOUND) {
            if (free_slot < 0) free_slot = (int)i;
            continue;
        }
        if (e != ESP_OK) continue;   /* unreadable slot: leave it alone */
        if (old.created > newest) newest = old.created;
        if (same < 0 && memcmp(old.rp_hash, rec->rp_hash, 32) == 0 && old.user_id_len == rec->user_id_len &&
            memcmp(old.user_id, rec->user_id, rec->user_id_len) == 0) {
            same = (int)i;
        }
    }
    int slot = same >= 0 ? same : free_slot;
    if (slot < 0) {
        nvs_close(h);
        return ESP_ERR_NO_MEM;
    }
    copy.ver = FIDO_RES_VER;
    copy.created = newest + 1;
    char key[8];
    res_key(key, (size_t)slot);
    err = nvs_set_blob(h, key, &copy, sizeof(copy));
    if (err == ESP_OK) err = nvs_commit(h);
    nvs_close(h);
    if (err == ESP_OK && same < 0) s_resident++;
    if (err == ESP_OK && slot_out) *slot_out = slot;
    return err;
}

esp_err_t store_resident_load(size_t idx, fido_resident_t *out)
{
    if (idx >= FIDO_MAX_RESIDENT || !out) return ESP_ERR_INVALID_ARG;
    nvs_handle_t h;
    esp_err_t err = nvs_open(NS, NVS_READONLY, &h);
    if (err != ESP_OK) return err;
    err = res_get(h, idx, out);
    nvs_close(h);
    return err;
}

esp_err_t store_resident_delete(size_t idx)
{
    if (idx >= FIDO_MAX_RESIDENT) return ESP_ERR_INVALID_ARG;
    nvs_handle_t h;
    esp_err_t err = nvs_open(NS, NVS_READWRITE, &h);
    if (err != ESP_OK) return err;
    char key[8];
    res_key(key, idx);
    err = nvs_erase_key(h, key);
    if (err == ESP_OK) err = nvs_commit(h);
    nvs_close(h);
    if (err == ESP_OK) count_resident();
    return err;
}

/* ---- PIN state ----
 * NVS "pin" = set (1) || retries (1) || min_len (1) || iv (16) || AES-256-CBC(kenc, iv, pinHash16) (16)
 *             || HMAC(kmac, all previous bytes) (32)
 * kenc = KDF("pin-enc"), kmac = KDF("pin-mac") under the effective master. Without flash encryption a
 * full flash dump contains the master (unless hardened), so this does not stop offline guessing from a
 * dump; it stops a plain NVS read or a partial dump from yielding the hash, and the MAC stops edits of
 * the retry counter. Once hardened, the keys depend on the eFuse key, which software cannot read. */
#define PIN_REC_LEN (3 + 16 + 16 + 32)

static esp_err_t pin_keys(uint8_t kenc[32], uint8_t kmac[32])
{
    esp_err_t err = store_kdf((const uint8_t *)"pin-enc", 7, kenc);
    if (err == ESP_OK) err = store_kdf((const uint8_t *)"pin-mac", 7, kmac);
    return err;
}

esp_err_t store_pin_load(store_pin_t *p)
{
    memset(p, 0, sizeof(*p));
    p->retries = STORE_PIN_RETRIES;
    p->min_len = 4;
    nvs_handle_t h;
    esp_err_t err = nvs_open(NS, NVS_READONLY, &h);
    if (err != ESP_OK) return err;
    uint8_t rec[PIN_REC_LEN];
    size_t len = sizeof(rec);
    err = nvs_get_blob(h, "pin", rec, &len);
    nvs_close(h);
    if (err == ESP_ERR_NVS_NOT_FOUND) return ESP_OK;
    if (err != ESP_OK) return err;
    uint8_t kenc[32], kmac[32], mac[32];
    err = pin_keys(kenc, kmac);
    if (err == ESP_OK && len == sizeof(rec)) err = cred_hmac(kmac, rec, PIN_REC_LEN - 32, mac);
    if (err == ESP_OK && (len != sizeof(rec) || !cred_ct_equal(mac, rec + PIN_REC_LEN - 32, 32))) {
        ESP_LOGE(TAG, "PIN record failed its integrity check: PIN blocked until reset");
        p->set = true;
        p->retries = 0;
    } else if (err == ESP_OK) {
        p->set = rec[0] != 0;
        p->retries = rec[1] > STORE_PIN_RETRIES ? 0 : rec[1];
        p->min_len = rec[2];
        if (p->set) err = cred_aes_cbc(false, kenc, rec + 3, rec + 19, 16, p->hash);
    }
    mbedtls_platform_zeroize(kenc, sizeof(kenc));
    mbedtls_platform_zeroize(kmac, sizeof(kmac));
    mbedtls_platform_zeroize(rec, sizeof(rec));
    return err;
}

esp_err_t store_pin_save(const store_pin_t *p)
{
    uint8_t rec[PIN_REC_LEN] = {0};
    uint8_t kenc[32], kmac[32];
    rec[0] = p->set ? 1 : 0;
    rec[1] = p->retries;
    rec[2] = p->min_len;
    cred_rng(rec + 3, 16);
    esp_err_t err = pin_keys(kenc, kmac);
    uint8_t zero[16] = {0};
    if (err == ESP_OK) err = cred_aes_cbc(true, kenc, rec + 3, p->set ? p->hash : zero, 16, rec + 19);
    if (err == ESP_OK) err = cred_hmac(kmac, rec, PIN_REC_LEN - 32, rec + PIN_REC_LEN - 32);
    mbedtls_platform_zeroize(kenc, sizeof(kenc));
    mbedtls_platform_zeroize(kmac, sizeof(kmac));
    nvs_handle_t h;
    if (err == ESP_OK) err = nvs_open(NS, NVS_READWRITE, &h);
    if (err == ESP_OK) {
        err = nvs_set_blob(h, "pin", rec, sizeof(rec));
        if (err == ESP_OK) err = nvs_commit(h);
        nvs_close(h);
    }
    mbedtls_platform_zeroize(rec, sizeof(rec));
    return err;
}
