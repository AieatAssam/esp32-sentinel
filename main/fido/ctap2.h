#pragma once

#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"

/* Handles one CTAP2 request on channel cid (req[0] is the command byte). Writes the status byte and the
 * CBOR response to out. Returns the total number of bytes written, status byte included. */
size_t ctap2_handle(uint32_t cid, const uint8_t *req, size_t len, uint8_t *out, size_t cap);
/* Boot-time state (pinUvAuthToken, PIN retry session state). Call once inside the entropy window. */
void ctap2_init(void);
/* Called about once a second and between messages: expires getNextAssertion state and token timers. */
void ctap2_tick(void);
/* Everything authenticatorReset clears: credentials, master, PIN, key-agreement keys, tokens. */
esp_err_t ctap2_reset_state(void);
/* store_harden(), then re-saves the PIN state under the keys of the new effective master. */
esp_err_t ctap2_harden(void);
