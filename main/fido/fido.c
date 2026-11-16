#include <string.h>
#include "esp_attr.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "driver/gpio.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "button.h"
#include "led.h"
#include "logbuf.h"
#include "recovery.h"
#include "usb_fido.h"
#include "ctaphid.h"
#include "ctap2.h"
#include "u2f.h"
#include "store.h"
#include "cred.h"
#include "fido.h"
#include "fido_priv.h"

/* bootloader_support is not in main's REQUIRES; these two are linked into every app anyway. */
void bootloader_random_enable(void);
void bootloader_random_disable(void);

static const char *TAG = "fido";

#define RX_DEPTH          32
#define TOUCH_TIMEOUT_MS  30000
/* Admin actions wait this long for BOOT. The web UI allows 35 s for these two calls. */
#define ADMIN_TOUCH_MS    30000
#define POLL_MS           10
#define KEEPALIVE_US      100000
#define LOCK_WAIT         pdMS_TO_TICKS(35000)
/* U2F (CTAP1) presence: requests get 0x6985 at once and the host polls. A press while a U2F request
 * was seen in the last U2F_WINDOW_US is latched for U2F_LATCH_US and used by the next request. */
#define U2F_WINDOW_US     2000000
#define U2F_LATCH_US      3000000

#define CTAP2_ERR_KEEPALIVE_CANCEL 0x2d
#define CTAP2_ERR_USER_TIMEOUT     0x2f
#define CTAP2_ERR_OPERATION_DENIED 0x27
#define CTAP1_ERR_OTHER            0x7f
#define KEEPALIVE_UP_NEEDED        0x02
#define BOOT_GPIO                  GPIO_NUM_0

/* Test-build presence grants. AUTO_UP: CTAP/U2F presence (CONFIG_FIDO_TEST_AUTO_UP). AUTO_ADMIN: admin
 * actions and the release download-mode press, only with both test flags. */
#if CONFIG_FIDO_TEST_AUTO_UP
#define AUTO_UP true
#else
#define AUTO_UP false
#endif
#if CONFIG_FIDO_TEST_AUTO_UP && CONFIG_EFUSE_VIRTUAL
#define AUTO_ADMIN true
#else
#define AUTO_ADMIN false
#endif
#define TAP_US                     30000     /* debounced press: a FIDO touch */
#define DL_HOLD_US                 3000000   /* download mode: BOOT held 3 s, as on the HTTP path */

static QueueHandle_t s_rx_q;
static SemaphoreHandle_t s_lock;
static volatile uint8_t s_state;          /* 0 idle, 1 busy, 2 touch */
static const char *const k_state_names[] = {"idle", "busy", "waiting_touch"};

/* Channel of the request in flight; used for KEEPALIVE and CANCEL. */
static uint32_t s_req_cid;
static bool s_drop_reply;                 /* INIT resynced the channel: the transaction is abandoned */
/* CTAP messages in PSRAM: they carry only wire data (PIN material arrives encrypted under the session
 * key). Keys, PIN state and the master key stay in internal RAM. */
static EXT_RAM_BSS_ATTR uint8_t s_req_buf[CTAPHID_MAX_MSG];
static EXT_RAM_BSS_ATTR uint8_t s_resp[CTAPHID_MAX_MSG + 1];

/* ---- BOOT button, sampled on the fido task. A press counts only after the button was seen released
 * since sampling (re)started, so a press made before a request, or a held button, never counts. ---- */
static bool s_btn_armed;
static int64_t s_btn_low_since;           /* 0: not held */

static void btn_restart(void)
{
    s_btn_armed = false;
    s_btn_low_since = 0;
}

/* True once the button has been held low for hold_us (time based, so it does not depend on how
 * often the caller polls). */
static bool btn_poll(int64_t hold_us)
{
    int64_t now = esp_timer_get_time();
    if (gpio_get_level(BOOT_GPIO) == 1) {
        s_btn_armed = true;
        s_btn_low_since = 0;
        return false;
    }
    if (!s_btn_armed) return false;
    if (!s_btn_low_since) s_btn_low_since = now;
    if (now - s_btn_low_since >= hold_us) {
        btn_restart();
        return true;
    }
    return false;
}

/* Set while another module (HTTP download-mode confirmation) waits on BOOT: one press must never
 * confirm two things, so FIDO presence and admin waits are refused meanwhile. Written under s_lock. */
static volatile bool s_btn_claimed;

bool fido_button_claim(void)
{
    if (!s_lock || !xSemaphoreTake(s_lock, 0)) return false;   /* a FIDO command or admin op is running */
    bool ok = !s_btn_claimed && s_state == 0;
    if (ok) s_btn_claimed = true;
    xSemaphoreGive(s_lock);
    return ok;
}

void fido_button_release(void)
{
    s_btn_claimed = false;
}

/* ---- U2F latch ---- */
static int64_t s_u2f_window_until;   /* 0: no U2F request waiting */
static int64_t s_u2f_latch_until;    /* 0: no latched press */

static void u2f_end(void)
{
    if (s_u2f_window_until || s_u2f_latch_until) {
        s_u2f_window_until = 0;
        s_u2f_latch_until = 0;
        s_state = 0;
        led_set_mode(led_get_mode());
    }
}

bool fido_u2f_presence(void)
{
    if (AUTO_UP) return true;
    if (s_btn_claimed) return false;   /* BOOT is claimed elsewhere: keep answering 6985 */
    int64_t now = esp_timer_get_time();
    if (s_u2f_latch_until && now < s_u2f_latch_until) {
        u2f_end();   /* one press, one request */
        return true;
    }
    if (!s_u2f_window_until) {
        btn_restart();
        led_set_mode(LED_FIDO_WAIT);
    }
    s_u2f_latch_until = 0;
    s_u2f_window_until = now + U2F_WINDOW_US;
    return false;
}

/* Called from the fido task loop between messages. */
static void u2f_tick(void)
{
    if (!s_u2f_window_until && !s_u2f_latch_until) return;
    int64_t now = esp_timer_get_time();
    if (s_u2f_latch_until) {
        if (now >= s_u2f_latch_until) u2f_end();
        return;
    }
    if (btn_poll(TAP_US)) {
        s_u2f_latch_until = now + U2F_LATCH_US;
        s_u2f_window_until = 0;
        led_set_mode(LED_FIDO_OK);
        return;
    }
    if (now >= s_u2f_window_until) u2f_end();
    else s_state = 2;
}

/* ---- CTAP2 presence wait ---- */

static uint8_t presence_wait(uint32_t timeout_ms, int64_t hold_us, bool auto_grant)
{
    if (auto_grant) {
        ESP_LOGW(TAG, "TEST BUILD: user presence auto-granted");
        return 0;
    }
    if (s_btn_claimed) return CTAP2_ERR_OPERATION_DENIED;   /* BOOT is confirming something else */
    u2f_end();
    btn_restart();
    s_state = 2;
    led_set_mode(LED_FIDO_WAIT);
    int64_t start = esp_timer_get_time();
    int64_t last_ka = start - KEEPALIVE_US;
    uint8_t result = CTAP2_ERR_USER_TIMEOUT;
    for (;;) {
        int64_t now = esp_timer_get_time();
        if (now - last_ka >= KEEPALIVE_US) {   /* by elapsed time, so steady traffic cannot starve it */
            uint8_t ka = KEEPALIVE_UP_NEEDED;
            ctaphid_send(s_req_cid, CTAPHID_KEEPALIVE, &ka, 1);
            last_ka = now;
        }
        if (btn_poll(hold_us)) {
            result = 0;
            break;
        }
        if (now - start >= (int64_t)timeout_ms * 1000) break;
        uint8_t pkt[64];
        if (xQueueReceive(s_rx_q, pkt, pdMS_TO_TICKS(POLL_MS)) != pdTRUE) continue;
        ctaphid_msg_t m;
        if (!ctaphid_rx(pkt, &m)) continue;
        if (m.cid == s_req_cid && m.cmd == CTAPHID_CANCEL) {
            result = CTAP2_ERR_KEEPALIVE_CANCEL;
            break;
        }
        if (m.cid == s_req_cid && m.cmd == CTAPHID_INIT) {
            /* Resync: the transaction is abandoned and gets no reply (CTAP 2.1 §11.2.9.1.3). */
            s_drop_reply = true;
            result = CTAP2_ERR_KEEPALIVE_CANCEL;
            break;
        }
        if (m.cmd != CTAPHID_KEEPALIVE && m.cmd != CTAPHID_INIT && m.cmd != CTAPHID_CANCEL) {
            ctaphid_send_error(m.cid, CTAPHID_ERR_CHANNEL_BUSY);
        }
    }
    s_state = 1;
    led_set_mode(led_get_mode());
    return result;
}

uint8_t fido_user_presence(void)
{
    return presence_wait(TOUCH_TIMEOUT_MS, TAP_US, AUTO_UP);
}

/* ---- message dispatch ---- */

static void vendor_download(const ctaphid_msg_t *m)
{
    if (m->len != 8 || memcmp(s_req_buf, "DOWNLOAD", 8) != 0) {
        ctaphid_send_error(m->cid, CTAPHID_ERR_INVALID_PAR);
        return;
    }
#if !CONFIG_DEV_BACKDOOR
    /* Release: someone at the device must hold BOOT for 3 s (a tap is a FIDO touch and does not count). The host sees KEEPALIVE UPNEEDED meanwhile.
     * The test builds' auto-grant applies only with both test flags, as for the admin actions. */
    ESP_LOGW(TAG, "CTAPHID download-mode request: waiting for BOOT");
    if (s_btn_claimed) {
        ctaphid_send_error(m->cid, CTAPHID_ERR_CHANNEL_BUSY);
        return;
    }
    uint8_t up = presence_wait(ADMIN_TOUCH_MS, DL_HOLD_US, AUTO_ADMIN);
    if (s_drop_reply) return;
    if (up) {   /* no press (timeout) or CANCEL */
        ctaphid_send_error(m->cid, CTAPHID_ERR_OTHER);
        return;
    }
#endif
    ESP_LOGW(TAG, "CTAPHID download-mode request");
    ctaphid_send(m->cid, m->cmd, (const uint8_t *)"OK", 2);
    vTaskDelay(pdMS_TO_TICKS(300));   /* let the IN report reach the host */
    recovery_reboot(true);
}

static void handle_message(const ctaphid_msg_t *m)
{
    /* m->data is reused by the next ctaphid_rx(), so copy first. */
    memcpy(s_req_buf, m->data, m->len);
    s_req_cid = m->cid;
    s_drop_reply = false;
    size_t len = m->len;

    switch (m->cmd) {
    case CTAPHID_PING:
        ctaphid_send(m->cid, CTAPHID_PING, s_req_buf, len);
        break;
    case CTAPHID_MSG:
    case CTAPHID_CBOR: {
        xSemaphoreTake(s_lock, portMAX_DELAY);
        s_state = 1;
        size_t rlen = (m->cmd == CTAPHID_MSG)
                          ? u2f_handle(s_req_buf, len, s_resp, sizeof(s_resp))
                          : ctap2_handle(s_req_cid, s_req_buf, len, s_resp, sizeof(s_resp));
        if (!s_u2f_window_until && !s_u2f_latch_until) s_state = 0;
        xSemaphoreGive(s_lock);
        if (!s_drop_reply) ctaphid_send(m->cid, m->cmd, s_resp, rlen);
        break;
    }
    case CTAPHID_VENDOR_DOWNLOAD:
        xSemaphoreTake(s_lock, portMAX_DELAY);
        vendor_download(m);
        s_state = 0;
        xSemaphoreGive(s_lock);
        break;
#if CONFIG_DEV_BACKDOOR
    case CTAPHID_VENDOR_LOG: {
        /* The ring is larger than one CTAPHID message, so it is paged: optional 4-byte
         * big-endian offset from the oldest byte; a reply shorter than CTAPHID_MAX_MSG is
         * the last page. ponytail: the ring can move between pages (lines may repeat or
         * skip at a page edge); fine for debugging, snapshot the ring if that matters. */
        size_t off = 0;
        if (len == 4) {
            off = ((size_t)s_req_buf[0] << 24) | ((size_t)s_req_buf[1] << 16) |
                  ((size_t)s_req_buf[2] << 8) | s_req_buf[3];
        } else if (len != 0) {
            ctaphid_send_error(m->cid, CTAPHID_ERR_INVALID_LEN);
            break;
        }
        ctaphid_send(m->cid, m->cmd, s_resp, logbuf_read_at(off, (char *)s_resp, CTAPHID_MAX_MSG));
        break;
    }
#endif
    case CTAPHID_INIT:      /* resync while idle: already answered */
    case CTAPHID_CANCEL:
    case CTAPHID_KEEPALIVE:
        break;   /* nothing in flight to cancel or keep alive */
    default:
        ctaphid_send_error(m->cid, CTAPHID_ERR_INVALID_CMD);
        break;
    }
}

static void fido_task(void *arg)
{
    (void)arg;
    uint8_t pkt[64];
    for (;;) {
        /* Poll fast only while a U2F request waits for a press; otherwise a 1 s tick for timers. */
        bool u2f = s_u2f_window_until || s_u2f_latch_until;
        if (xQueueReceive(s_rx_q, pkt, pdMS_TO_TICKS(u2f ? POLL_MS : 1000)) == pdTRUE) {
            ctaphid_msg_t m;
            if (ctaphid_rx(pkt, &m)) handle_message(&m);
        }
        if (xSemaphoreTake(s_lock, 0) == pdTRUE) {   /* not while an admin action owns the button */
            u2f_tick();
            ctap2_tick();
            xSemaphoreGive(s_lock);
        }
    }
}

void fido_init(void)
{
    if (s_rx_q) return;
    s_lock = xSemaphoreCreateMutex();
    s_rx_q = xQueueCreate(RX_DEPTH, 64);
    if (!s_lock || !s_rx_q) {
        ESP_LOGE(TAG, "queue/mutex allocation failed");
        return;
    }
    gpio_config_t io = {
        .pin_bit_mask = 1ULL << BOOT_GPIO,
        .mode = GPIO_MODE_INPUT,
        .pull_up_en = GPIO_PULLUP_ENABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE,
    };
    gpio_config(&io);

    /* Key material made here (master on first boot, key-agreement keys, the RNG pool that later key
     * generation draws on) needs a true entropy source. Wi-Fi/BT are not up yet and the SAR ADC is unused
     * (the temperature sensor starts in sensing_start), so the IDF-documented way is to enable the
     * internal entropy source for this window (ESP-IDF "Random Number Generation", Startup). */
    bootloader_random_enable();
    cred_rng_seed();
    esp_err_t serr = store_init();
    /* PIN/UV auth protocol initialize(): fresh key-agreement keys and pinUvAuthToken each boot. */
    bool ka_ok = serr == ESP_OK && cred_ka_regen() == ESP_OK;
    if (serr == ESP_OK) ctap2_init();
    bootloader_random_disable();
    if (serr != ESP_OK) {
        ESP_LOGE(TAG, "store init failed; FIDO disabled");
        return;
    }
    if (!ka_ok) ESP_LOGE(TAG, "key agreement keygen failed; clientPIN and hmac-secret unavailable");
    ctaphid_init();
    if (xTaskCreate(fido_task, "fido", 16384, NULL, 5, NULL) != pdPASS) {
        ESP_LOGE(TAG, "task create failed");
    }
}

void fido_hid_report_rx(const uint8_t *data, size_t len)
{
    if (!s_rx_q || !data || len != 64) return;
    /* Only copies into the queue; all parsing happens on the fido task. */
    xQueueSend(s_rx_q, data, 0);
}

const char *fido_state_str(void)
{
    return k_state_names[s_state < 3 ? s_state : 0];
}

/* Runs an admin action under the command lock, after a BOOT press within ADMIN_TOUCH_MS. */
static esp_err_t admin_with_touch(esp_err_t (*op)(void))
{
    if (!s_lock) return ESP_ERR_INVALID_STATE;
    if (!xSemaphoreTake(s_lock, LOCK_WAIT)) return ESP_ERR_TIMEOUT;
    if (s_btn_claimed) {
        xSemaphoreGive(s_lock);
        return ESP_ERR_INVALID_STATE;
    }
    u2f_end();
    s_state = 2;
    led_set_mode(LED_FIDO_WAIT);
    esp_err_t err = ESP_ERR_TIMEOUT;
#if CONFIG_FIDO_TEST_AUTO_UP && CONFIG_EFUSE_VIRTUAL
    /* TEST BUILD ONLY (both flags): admin ops run without a BOOT press so the virtual-eFuse
     * harden can be exercised on a board with no operator. Normal builds keep the press wait. */
    ESP_LOGW(TAG, "TEST BUILD: admin touch auto-granted");
    err = op();
#else
    if (button_wait_press(ADMIN_TOUCH_MS)) err = op();
#endif
    led_set_mode(led_get_mode());
    s_state = 0;
    xSemaphoreGive(s_lock);
    return err;
}

/* Reset clears everything a CTAP reset clears. */
static esp_err_t reset_all(void)
{
    return ctap2_reset_state();
}

esp_err_t fido_admin_reset(void)
{
    return admin_with_touch(reset_all);
}

esp_err_t fido_admin_harden(void)
{
    return admin_with_touch(ctap2_harden);
}

uint32_t fido_credential_count(void)
{
    return store_resident_count();
}

bool fido_is_hardened(void)
{
    return store_is_hardened();
}
