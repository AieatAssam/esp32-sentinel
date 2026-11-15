#pragma once

#include <stdbool.h>
#include <stdint.h>

/* Waits for a BOOT button press while keeping the active request alive on USB.
 * Returns 0 on press, or a CTAP2 status: 0x2d (cancelled) or 0x2f (timed out). */
uint8_t fido_user_presence(void);

/* U2F presence, classic CTAP1 behaviour: true when a press was latched for this request (and consumes
 * it); otherwise starts or extends the press window and returns false, and the request answers 0x6985
 * at once so the host polls. */
bool fido_u2f_presence(void);
