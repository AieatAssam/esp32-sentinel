#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"

/* Joined-mode link state, as reported by GET /api/wifi and the frame's "link" field. */
typedef struct {
    const char *mode;     /* "passive" or "joined" */
    const char *state;    /* "off", "connecting", "connected", "failed" */
    bool has_ssid;
    char ssid[33];
    bool has_reason;
    char reason[24];
    float rate;           /* CSI frames/s from the joined AP (0 when not joined) */
} sensing_link_t;

/* Starts the passive radio sensing task (Wi-Fi promiscuous + CSI, NimBLE observer, ICMP keepalive). */
void sensing_start(void);
/* Smoothed motion 0..1 (same value as the frame's "motion"). */
float sensing_motion(void);
/* Chip temperature in deg C, read once a second; NaN until the first read. */
float sensing_temp_get(void);
/* Writes the current sensing frame as JSON into buf. Returns the length written (excluding NUL).
 * Entries that do not fit are dropped; the output is always valid JSON. */
size_t sensing_snapshot_json(char *buf, size_t len);
/* Starts a ~10 s empty-room baseline capture (POST /api/calibrate). */
void sensing_calibrate_start(void);
/* Clears the stored baseline (POST /api/calibrate?clear=1). */
void sensing_calibrate_clear(void);

/* Joined mode. The password is stored in NVS namespace "wifi" and never returned. */
esp_err_t sensing_wifi_join(const char *ssid, const char *pass);
void sensing_wifi_forget(void);
void sensing_link_get(sensing_link_t *out);
