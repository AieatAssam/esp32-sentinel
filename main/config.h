#pragma once

#include <stdbool.h>
#include "esp_err.h"

typedef struct {
    bool autolock;
    int away_secs;            /* 5..600 */
    float motion_threshold;   /* 0..1 */
    char lock_os[8];          /* "mac" | "win" | "linux" */
    int led_gpio;             /* 38 or 48 */
    int led_brightness;       /* 0..255 */
    int channel;              /* 0 = auto, else 1..13 */
    bool use_breathing;       /* default false: show breathing and count it as presence */
    bool use_baseline;        /* default false: empty-room baseline (nearness) in presence */
    float near_threshold;     /* 0..1; appended last: a blob stored without it still loads */
} app_config_t;

/* Loads the config from NVS (defaults when absent or invalid). Call after nvs_flash_init(). */
esp_err_t config_init(void);
const app_config_t *config_get(void);
/* Validates, applies and persists to NVS. Returns ESP_ERR_INVALID_ARG on out-of-range values. */
esp_err_t config_set(const app_config_t *c);
/* Writes a deferred (coalesced) config change to NVS now. Called before every reboot. */
void config_flush(void);
