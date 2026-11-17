#include "config.h"

#include <stddef.h>
#include <string.h>
#include "nvs.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"

static const char *TAG = "config";
#define NVS_NS "app"
#define NVS_KEY "cfg"

/* LED data pins allowed for the onboard WS2812 (ESP32-S3 DevKit: 48, some boards: 38). */
static const int s_led_gpio_allow[] = {38, 48};

static app_config_t s_cfg = {
    .autolock = false,
    .away_secs = 30,
    .motion_threshold = 0.15f,
    .lock_os = "mac",
    .led_gpio = 48,
    .led_brightness = 32,
    .channel = 0,
    .use_breathing = false,
    .use_baseline = false,
    .near_threshold = 0.40f,
    .use_ble = false,
    .ble_near_dbm = -55,
};

_Static_assert(offsetof(app_config_t, near_threshold) == 36, "size of the stored blob before near_threshold");
_Static_assert(offsetof(app_config_t, use_ble) == 40, "size of the stored blob before use_ble");

static esp_err_t validate(const app_config_t *c)
{
    if (c->away_secs < 5 || c->away_secs > 600) return ESP_ERR_INVALID_ARG;
    if (!(c->motion_threshold >= 0.0f && c->motion_threshold <= 1.0f)) return ESP_ERR_INVALID_ARG;
    if (!(c->near_threshold >= 0.0f && c->near_threshold <= 1.0f)) return ESP_ERR_INVALID_ARG;
    if (c->ble_near_dbm < -80 || c->ble_near_dbm > -30) return ESP_ERR_INVALID_ARG;
    if (strnlen(c->lock_os, sizeof(c->lock_os)) >= sizeof(c->lock_os)) return ESP_ERR_INVALID_ARG;
    if (strcmp(c->lock_os, "mac") && strcmp(c->lock_os, "win") && strcmp(c->lock_os, "linux")) {
        return ESP_ERR_INVALID_ARG;
    }
    bool gpio_ok = false;
    for (size_t i = 0; i < sizeof(s_led_gpio_allow) / sizeof(s_led_gpio_allow[0]); i++) {
        if (c->led_gpio == s_led_gpio_allow[i]) gpio_ok = true;
    }
    if (!gpio_ok) return ESP_ERR_INVALID_ARG;
    if (c->led_brightness < 0 || c->led_brightness > 255) return ESP_ERR_INVALID_ARG;
    if (c->channel != 0 && (c->channel < 1 || c->channel > 13)) return ESP_ERR_INVALID_ARG;
    return ESP_OK;
}

esp_err_t config_init(void)
{
    nvs_handle_t h;
    esp_err_t err = nvs_open(NVS_NS, NVS_READONLY, &h);
    if (err != ESP_OK) {
        ESP_LOGI(TAG, "no stored config, using defaults (%s)", esp_err_to_name(err));
        return ESP_OK;
    }
    app_config_t stored = s_cfg;     /* a shorter blob from older firmware keeps the defaults of the later fields */
    size_t len = sizeof(stored);
    err = nvs_get_blob(h, NVS_KEY, &stored, &len);
    nvs_close(h);
    bool len_ok = len == sizeof(stored) || len == offsetof(app_config_t, near_threshold) ||
                  len == offsetof(app_config_t, use_ble);
    if (err == ESP_OK && len_ok && validate(&stored) == ESP_OK) {
        s_cfg = stored;
        ESP_LOGI(TAG, "config loaded from NVS");
    } else {
        ESP_LOGW(TAG, "stored config absent or invalid, using defaults");
    }
    return ESP_OK;
}

const app_config_t *config_get(void)
{
    return &s_cfg;
}

/* L5: NVS already skips a write whose value is unchanged (nvs_storage.cpp writeItem compares).
 * Distinct values are written at most once per CONFIG_WRITE_MIN_US: a faster change is applied
 * in RAM at once and its write coalesced into one deferred write. */
#define CONFIG_WRITE_MIN_US (1000LL * 1000)
static portMUX_TYPE s_cfg_mux = portMUX_INITIALIZER_UNLOCKED;   /* guards s_cfg writes and the flush copy */
static int64_t s_last_write_us = -CONFIG_WRITE_MIN_US;
static esp_timer_handle_t s_flush_t;

static esp_err_t write_nvs(const app_config_t *c)
{
    nvs_handle_t h;
    esp_err_t err = nvs_open(NVS_NS, NVS_READWRITE, &h);
    if (err != ESP_OK) return err;
    err = nvs_set_blob(h, NVS_KEY, c, sizeof(*c));
    if (err == ESP_OK) err = nvs_commit(h);
    nvs_close(h);
    s_last_write_us = esp_timer_get_time();
    return err;
}

static void flush_cb(void *arg)
{
    (void)arg;
    app_config_t c;
    portENTER_CRITICAL(&s_cfg_mux);
    c = s_cfg;
    portEXIT_CRITICAL(&s_cfg_mux);
    esp_err_t err = write_nvs(&c);
    if (err != ESP_OK) ESP_LOGE(TAG, "deferred config write failed: %s", esp_err_to_name(err));
}

void config_flush(void)
{
    if (s_flush_t && esp_timer_is_active(s_flush_t) && esp_timer_stop(s_flush_t) == ESP_OK) flush_cb(NULL);
}

esp_err_t config_set(const app_config_t *c)
{
    esp_err_t err = validate(c);
    if (err != ESP_OK) return err;

    int64_t wait = s_last_write_us + CONFIG_WRITE_MIN_US - esp_timer_get_time();
    if (!s_flush_t) {
        esp_timer_create_args_t a = {.callback = flush_cb, .name = "cfg_flush"};
        if (esp_timer_create(&a, &s_flush_t) != ESP_OK) s_flush_t = NULL;
    }
    if (wait <= 0 && !(s_flush_t && esp_timer_is_active(s_flush_t))) {
        err = write_nvs(c);              /* not applied when it cannot be stored */
        if (err != ESP_OK) return err;
    } else if (!s_flush_t || (!esp_timer_is_active(s_flush_t) &&
                              esp_timer_start_once(s_flush_t, wait > 0 ? (uint64_t)wait : 1) != ESP_OK)) {
        return ESP_ERR_NO_MEM;
    }
    /* Writers are the HTTP task only; readers tolerate a torn read. The lock only keeps the
     * deferred flush from copying half an update. */
    portENTER_CRITICAL(&s_cfg_mux);
    s_cfg = *c;
    portEXIT_CRITICAL(&s_cfg_mux);
    return ESP_OK;
}
