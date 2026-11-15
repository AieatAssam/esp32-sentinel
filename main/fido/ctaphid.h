#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define CTAPHID_MAX_MSG 7609
#define CTAPHID_BROADCAST 0xffffffffu

#define CTAPHID_PING      0x01
#define CTAPHID_MSG       0x03
#define CTAPHID_LOCK      0x04
#define CTAPHID_INIT      0x06
#define CTAPHID_WINK      0x08
#define CTAPHID_CBOR      0x10
#define CTAPHID_CANCEL    0x11
#define CTAPHID_KEEPALIVE 0x3b
#define CTAPHID_ERROR     0x3f
/* Vendor commands (0x40..0x7f). Recovery paths that work with no network. */
#define CTAPHID_VENDOR_DOWNLOAD 0x51   /* payload "DOWNLOAD" -> "OK", reboot to ROM download. Release builds
                                          wait for a BOOT press first (KEEPALIVE UPNEEDED while waiting). */
#define CTAPHID_VENDOR_LOG      0x52   /* CONFIG_DEV_BACKDOOR only: [u32 BE offset] -> RAM log page */

#define CTAPHID_ERR_INVALID_CMD  0x01
#define CTAPHID_ERR_INVALID_PAR  0x02
#define CTAPHID_ERR_INVALID_LEN  0x03
#define CTAPHID_ERR_INVALID_SEQ  0x04
#define CTAPHID_ERR_CHANNEL_BUSY 0x06
#define CTAPHID_ERR_INVALID_CHANNEL 0x0b
#define CTAPHID_ERR_OTHER        0x7f

typedef struct {
    uint32_t cid;
    uint8_t cmd;
    size_t len;
    const uint8_t *data;   /* valid until the next ctaphid_rx() call */
} ctaphid_msg_t;

void ctaphid_init(void);
/* Feeds one 64-byte OUT report. Returns true when a complete message is in *out.
 * INIT is answered here. INIT on an allocated channel (resync) is also returned, with len 0, so a caller
 * waiting on that channel can abandon its transaction; broadcast INIT is never returned. */
bool ctaphid_rx(const uint8_t pkt[64], ctaphid_msg_t *out);
/* Sends a complete message as init + continuation reports. */
void ctaphid_send(uint32_t cid, uint8_t cmd, const uint8_t *data, size_t len);
void ctaphid_send_error(uint32_t cid, uint8_t err);

