#pragma once

#include <stddef.h>
#include <stdint.h>

/* Handles one U2F APDU carried in a CTAPHID MSG. Writes the response data and status word to out.
 * Returns the number of bytes written. */
size_t u2f_handle(const uint8_t *apdu, size_t len, uint8_t *out, size_t cap);
