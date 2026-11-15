#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"

/* Starts the CTAPHID task. Call after nvs_flash_init(). */
void fido_init(void);
/* Receives one CTAPHID OUT report (64 bytes) from the FIDO HID interface. Safe before fido_init(). */
void fido_hid_report_rx(const uint8_t *data, size_t len);
/* "idle", "busy" (command running) or "waiting_touch" (waiting for the BOOT button). */
const char *fido_state_str(void);

/* Admin actions for the web UI. Each waits up to 30 s for a BOOT press and returns ESP_ERR_TIMEOUT without one. */
esp_err_t fido_admin_reset(void);
/* Burns the eFuse key. Irreversible. Credentials registered before this stop working. */
esp_err_t fido_admin_harden(void);
uint32_t fido_credential_count(void);
bool fido_is_hardened(void);

/* BOOT button arbitration for other modules (HTTP download-mode confirmation). claim returns false when a
 * FIDO prompt, command or admin action is in progress or the button is already claimed; while claimed,
 * FIDO touch prompts answer OPERATION_DENIED (U2F: 6985), admin actions ESP_ERR_INVALID_STATE and HID
 * download mode CHANNEL_BUSY. Release after the wait ends, whatever its outcome. */
bool fido_button_claim(void);
void fido_button_release(void);

/* clientPIN state for status displays: whether a PIN is set, and the retries left (8 when unset). */
bool fido_pin_is_set(void);
uint8_t fido_pin_retries(void);
