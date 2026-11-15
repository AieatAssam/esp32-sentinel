#pragma once

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

/* Sends one 64-byte CTAPHID report on the FIDO interface IN endpoint.
 * Returns false when the host is not ready or the endpoint is busy. */
bool usb_fido_send_report(const uint8_t report[64]);

/* Called by usb.c for every OUT report on the FIDO interface; forwards to fido_hid_report_rx(). */
void usb_fido_on_out(const uint8_t *data, size_t len);
