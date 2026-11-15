#pragma once

#include <stdbool.h>
#include <stdint.h>

/* Blocks until a fresh press of the BOOT button (GPIO0, debounced) or until
 * timeout_ms elapses. A button already held when called does not count.
 * timeout_ms == 0 waits forever. Returns true on press, false on timeout. */
bool button_wait_press(uint32_t timeout_ms);
/* As button_wait_press, but the fresh press must be held for hold_ms without release. Used where
 * a short tap must not count (a FIDO touch is a short tap). */
bool button_wait_hold(uint32_t timeout_ms, uint32_t hold_ms);
