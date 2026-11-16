#include <string.h>
#include "esp_attr.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_timer.h"
#include "esp_log.h"
#include "esp_random.h"
#include "usb_fido.h"
#include "ctaphid.h"

static const char *TAG = "ctaphid";

#define INIT_DATA_MAX 57
#define CONT_DATA_MAX 59
#define CONT_TIMEOUT_US 500000

typedef struct {
    bool active;
    uint32_t cid;
    uint8_t cmd;
    size_t bcnt;
    size_t got;
    uint8_t next_seq;
    int64_t last_us;
    uint8_t buf[CTAPHID_MAX_MSG];
} asm_t;

static EXT_RAM_BSS_ATTR asm_t s_asm;     /* PSRAM: wire data only, task context */

/* Allocated channels. Random ids; the least recently used is dropped when a new one is needed. */
#define MAX_CHANNELS 8
static struct {
    uint32_t cid;    /* 0: free */
    uint32_t used;
} s_ch[MAX_CHANNELS];
static uint32_t s_use_clock;

static bool ch_touch(uint32_t cid)
{
    if (cid == 0 || cid == CTAPHID_BROADCAST) return false;
    for (int i = 0; i < MAX_CHANNELS; i++) {
        if (s_ch[i].cid == cid) {
            s_ch[i].used = ++s_use_clock;
            return true;
        }
    }
    return false;
}

static uint32_t alloc_cid(void)
{
    uint32_t cid;
    do {
        cid = esp_random();
    } while (cid == 0 || cid == CTAPHID_BROADCAST || ch_touch(cid));
    int victim = 0;
    for (int i = 1; i < MAX_CHANNELS; i++) {
        if (s_ch[i].used < s_ch[victim].used) victim = i;   /* free slots have used == 0 */
    }
    s_ch[victim].cid = cid;
    s_ch[victim].used = ++s_use_clock;
    return cid;
}

static void put_cid(uint8_t *p, uint32_t cid)
{
    p[0] = cid >> 24; p[1] = cid >> 16; p[2] = cid >> 8; p[3] = cid;
}

static uint32_t get_cid(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

static void send_report(const uint8_t rep[64])
{
    /* The endpoint is busy only briefly; retry for a short while before giving up. */
    for (int i = 0; i < 500; i++) {
        if (usb_fido_send_report(rep)) return;
        vTaskDelay(1);
    }
    ESP_LOGW(TAG, "report dropped: IN endpoint stayed busy");
}

void ctaphid_init(void)
{
    memset(&s_asm, 0, sizeof(s_asm));
    memset(s_ch, 0, sizeof(s_ch));
}

void ctaphid_send_error(uint32_t cid, uint8_t err)
{
    ctaphid_send(cid, CTAPHID_ERROR, &err, 1);
}

void ctaphid_send(uint32_t cid, uint8_t cmd, const uint8_t *data, size_t len)
{
    if (len > CTAPHID_MAX_MSG) return;
    uint8_t rep[64];
    memset(rep, 0, sizeof(rep));
    put_cid(rep, cid);
    rep[4] = cmd | 0x80;
    rep[5] = (uint8_t)(len >> 8);
    rep[6] = (uint8_t)len;
    size_t n = len < INIT_DATA_MAX ? len : INIT_DATA_MAX;
    if (n) memcpy(rep + 7, data, n);
    send_report(rep);
    size_t off = n;
    uint8_t seq = 0;
    while (off < len) {
        memset(rep, 0, sizeof(rep));
        put_cid(rep, cid);
        rep[4] = seq++ & 0x7f;
        n = len - off < CONT_DATA_MAX ? len - off : CONT_DATA_MAX;
        memcpy(rep + 5, data + off, n);
        send_report(rep);
        off += n;
    }
}

static void handle_init(uint32_t cid, const uint8_t *nonce8)
{
    uint8_t out[17];
    memcpy(out, nonce8, 8);
    uint32_t new_cid = (cid == CTAPHID_BROADCAST) ? alloc_cid() : cid;
    put_cid(out + 8, new_cid);
    out[12] = 2;      /* CTAPHID protocol version */
    out[13] = 1;      /* device major */
    out[14] = 0;      /* device minor */
    out[15] = 1;      /* device build */
    out[16] = 0x04;   /* CAPABILITY_CBOR; no WINK, no NMSG */
    /* INIT response always goes on the requesting channel, carrying the new cid. */
    ctaphid_send(cid, CTAPHID_INIT, out, sizeof(out));
}

static void reset_asm(void)
{
    s_asm.active = false;
}

bool ctaphid_rx(const uint8_t pkt[64], ctaphid_msg_t *out)
{
    uint32_t cid = get_cid(pkt);
    int64_t now = esp_timer_get_time();
    if (s_asm.active && now - s_asm.last_us > CONT_TIMEOUT_US) reset_asm();

    if (pkt[4] & 0x80) {
        uint8_t cmd = pkt[4] & 0x7f;
        size_t bcnt = ((size_t)pkt[5] << 8) | pkt[6];
        bool known = ch_touch(cid);

        if (cid != CTAPHID_BROADCAST && !known) {
            /* Channel 0 is reserved and other ids must come from INIT (CTAP 2.1 §11.2.3). */
            ctaphid_send_error(cid, CTAPHID_ERR_INVALID_CHANNEL);
            return false;
        }
        /* INIT is handled at once: allocation on broadcast, resync on an allocated channel. */
        if (cmd == CTAPHID_INIT) {
            if (bcnt != 8) {
                ctaphid_send_error(cid, CTAPHID_ERR_INVALID_LEN);
                return false;
            }
            if (s_asm.active && s_asm.cid == cid) reset_asm();
            handle_init(cid, pkt + 7);
            if (cid == CTAPHID_BROADCAST) return false;
            out->cid = cid;
            out->cmd = CTAPHID_INIT;
            out->len = 0;
            out->data = s_asm.buf;
            return true;
        }
        if (cid == CTAPHID_BROADCAST) {   /* broadcast carries INIT only */
            ctaphid_send_error(cid, CTAPHID_ERR_INVALID_CHANNEL);
            return false;
        }
        if (s_asm.active && s_asm.cid != cid) {
            /* A second channel tries to talk while another message is still assembling. */
            ctaphid_send_error(cid, CTAPHID_ERR_CHANNEL_BUSY);
            return false;
        }
        if (bcnt > CTAPHID_MAX_MSG) {
            ctaphid_send_error(cid, CTAPHID_ERR_INVALID_LEN);
            reset_asm();
            return false;
        }
        s_asm.active = true;
        s_asm.cid = cid;
        s_asm.cmd = cmd;
        s_asm.bcnt = bcnt;
        size_t n = bcnt < INIT_DATA_MAX ? bcnt : INIT_DATA_MAX;
        memcpy(s_asm.buf, pkt + 7, n);
        s_asm.got = n;
        s_asm.next_seq = 0;
        s_asm.last_us = now;
    } else {
        if (!s_asm.active || s_asm.cid != cid) {
            /* Stray continuation: ignore, per spec there is nothing to attach it to. */
            return false;
        }
        if (pkt[4] != s_asm.next_seq) {
            ctaphid_send_error(cid, CTAPHID_ERR_INVALID_SEQ);
            reset_asm();
            return false;
        }
        size_t remain = s_asm.bcnt - s_asm.got;
        size_t n = remain < CONT_DATA_MAX ? remain : CONT_DATA_MAX;
        memcpy(s_asm.buf + s_asm.got, pkt + 5, n);
        s_asm.got += n;
        s_asm.next_seq++;
        s_asm.last_us = now;
    }

    if (s_asm.got < s_asm.bcnt) return false;
    out->cid = s_asm.cid;
    out->cmd = s_asm.cmd;
    out->len = s_asm.bcnt;
    out->data = s_asm.buf;
    reset_asm();
    return true;
}
