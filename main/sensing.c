/* Radio sensing: Wi-Fi CSI (ambient OFDM frames, and the joined AP when opted in), beacon RSSI,
 * breathing, optional empty-room baseline, presence/away with optional autolock, a passive BLE
 * observer table, and the joined-mode Wi-Fi link. Published as the 10 Hz WebSocket frame. */
#include "sensing.h"

#include <errno.h>
#include <math.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "esp_event.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "fido/fido.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "host/ble_gap.h"
#include "host/ble_hs.h"
#include "host/ble_hs_adv.h"
#include "host/ble_hs_id.h"
#include "led.h"
#include "lock.h"
#include "lwip/sockets.h"
#include "net_policy.h"
#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "nvs.h"
#include "recovery.h"
#include "sensing_dsp.h"
#include "driver/temperature_sensor.h"
#include "threats.h"

static const char *TAG = "sensing";

/* ---------- tunables (all in one place, reported in the final report) ---------- */
#define AP_TABLE          16      /* tracked BSSIDs; frame shows the strongest AP_OUT */
#define AP_OUT            12
#define AP_AGE_US         (60LL * 1000000)   /* an AP not seen for this long is dropped */
#define BLE_TABLE         24
#define BLE_TTL_US        (30LL * 1000000)
#define BLE_SCAN_ITVL     160     /* 0.625 ms units: 100 ms interval */
#define BLE_SCAN_WIN      48      /* 30 ms window: ~30 % duty to limit Wi-Fi coexistence cost */
#define RSSI_RING         64      /* beacon RSSI samples kept per AP */
#define RSSI_WIN_US       (3LL * 1000000)
#define RSSI_SD_FLOOR     0.7f    /* dB: RSSI is whole dBm, so below this spread is quantisation */
#define RSSI_SD_FULL      3.0f    /* dB spread that maps to motion 1.0 */
#define CSI_TAU_S         3.0f    /* EWMA time constant of per-subcarrier mean and variance */
#define CSI_WARM          20      /* CSI samples needed before an AP's CSI stats are used */
#define CSI_MIN_FPS       2.0f    /* below this an AP's CSI is not used for motion or baseline */
#define CSI_MOTION_FULL   0.08f   /* mean per-subcarrier std of normalised amplitude that maps to 1.0 */
#define BASE_SHAPE_FULL   0.10f   /* mean abs shape difference that maps to baseline dev 1.0 */
#define BR_N              300     /* 30 s of 10 Hz breathing series */
#define BR_BIN_US         100000LL/* breathing bins: 100 ms of CSI averaged into one sample */
#define BR_WIN_US         (30LL * 1000000)
#define BR_GAP_US         (2LL * 1000000)  /* a gap longer than this in the window blocks breathing; shorter is interpolated */
#define BR_MIN_FPS        1.5f    /* mean CSI rate over the window needed to attempt breathing */
#define BR_MOTION_MAX     0.5f    /* breathing is withheld when motion is above this */
#define BR_CONF_SHOW      0.2f    /* breath is shown only above this conf */
#define BR_CONF_PRESENT   0.5f    /* breathing counts as presence above this conf */
#define MOTION_EWMA       0.3f    /* per 100 ms tick */
#define BASE_DB_FULL      4.0f    /* RSSI shift from baseline that maps to dev 1.0 (no CSI) */
#define BASE_DEV_PRESENT  0.5f    /* baseline dev that counts as presence */
#define BASE_CAPTURE_S    10
#define BASE_MIN_SAMPLES  5
#define BEACON_MIN_FPS    1.0f    /* total beacon rate below this counts as a collapse */
#define BEACON_LOW_S      30      /* collapse must last this long before a rescan */
#define REPICK_US         (180LL * 1000000)  /* at most one rescan per 3 min */
#define JOIN_TRIES        3
#define PING_PERIOD_MS   50       /* 20 Hz ICMP echo to the joined gateway */
#define DIST_RSSI_1M      (-40.0f)
#define DIST_N            2.5f    /* log-distance path-loss exponent */
#define TICK_MS           100

/* ---------- state ---------- */

typedef struct {
    bool used;
    uint8_t bssid[6];
    char ssid[33];
    uint8_t ch;
    int8_t rssi;
    bool prot;                    /* beacon advertises a privacy bit or RSN/WPA IE */
    uint32_t beacons;
    int64_t last_seen_us;
    /* trust (M4): only trusted APs feed presence; spoofed ones never do */
    int64_t learn_start_us;       /* start of the current run of steady beacons */
    thr_bcn_t bcn;                /* beacon seq/TSF consistency */
    bool spoof;                   /* inconsistent beacon stream on this BSSID */
    bool trusted;                 /* set by the tick: baseline, joined AP, or learned */
    uint32_t csi_dl, csi_ul;      /* attributed CSI frames: downlink (fed to stats), uplink (counted only) */
    uint32_t csi_prev;
    float csi_fps;                /* downlink CSI frames/s over the last 1 s */
    int8_t rssi_s[RSSI_RING];
    int64_t rssi_t[RSSI_RING];
    int rssi_head, rssi_n;
    /* CSI, time-weighted EWMA per subcarrier (irregular frame timestamps) */
    int64_t ewma_t;
    int ewma_n;
    float mu[64], var[64];        /* normalised amplitude mean and variance */
    uint8_t csi_disp[64], pdp_disp[16];
    /* breathing: 100 ms bins of mean CSI amplitude, PSRAM */
    float bin_sum;
    int bin_n;
    int64_t bin_t0;
    float *br_v;
    int64_t *br_t;
    uint16_t *br_c;
    int br_head, br_n;
    /* baseline */
    bool base_set, base_has_shape;
    float base_rssi;
    uint8_t base_shape[64];       /* mean normalised amplitude, x128 */
    float cap_sum;                /* RSSI accumulators during a capture */
    uint32_t cap_n;
    /* published (written by the tick, under s_mux) */
    float motion, motion_rssi, motion_csi;
    float breath_bpm, breath_conf;
} ap_t;

typedef struct {
    bool used;
    uint8_t addr[6];
    char name[25];
    float rssi;
    int64_t last_us;
    int64_t first_us;             /* start of the current continuous presence (see threats.c) */
    uint8_t kind;                 /* trk_kind_t from the advert, TRK_NONE when ordinary */
} ble_t;

typedef struct {
    uint8_t bssid[6];
    uint8_t valid;
    uint8_t has_shape;
    float rssi;
    uint8_t shape[64];
} base_entry_t;
typedef struct { uint32_t magic; uint32_t n; base_entry_t e[AP_TABLE]; } base_blob_t;
#define BASE_MAGIC 0x42415332u   /* "BAS2": layout with CSI shape */
#define NVS_NS "app"
#define NVS_BASE_KEY "base"
#define NVS_WIFI_NS "wifi"

typedef enum { LINK_OFF, LINK_CONNECTING, LINK_CONNECTED, LINK_FAILED } link_state_t;
static const char *const s_link_names[] = {"off", "connecting", "connected", "failed"};

static portMUX_TYPE s_mux = portMUX_INITIALIZER_UNLOCKED;
static ap_t s_ap[AP_TABLE];
static ble_t s_ble[BLE_TABLE];
static base_entry_t s_store[AP_TABLE];    /* persisted baseline, keyed by BSSID */
static uint32_t s_csi_total, s_csi_unattr, s_csi_ul_total, s_beacon_total;
static uint32_t s_hist_sig[4], s_hist_rate[32];
static float s_beacon_rate;                /* guarded by s_mux; set by the tick */
static volatile uint8_t s_channel;
static uint8_t s_passive_ch;               /* guarded by s_mux */
static float s_motion_raw, s_motion;       /* guarded by s_mux */
static float s_base_dev;                   /* guarded by s_mux */
static bool s_cal_active;                  /* guarded by s_mux */
static int64_t s_cal_end_us;
static int64_t s_last_active_us;           /* guarded by s_mux; written by tick */
static bool s_present = true;
static int s_away_in = -1;                 /* -1 = null */
static const char *s_why;                  /* NULL = null */
static const char *s_fault;                /* non-NULL: sensing cannot run (frame stub + fault) */
static bool s_br_visible;
static float s_br_bpm, s_br_conf;
static const char *s_br_state = "off";     /* off | listening | motion | found, sent in the frame */
static uint32_t s_ping_tx, s_ping_rx;      /* ICMP echo requests sent / echo replies seen, 5 s log */
static float s_cos[64][16], s_sin[64][16];  /* IDFT twiddles for the PDP, filled at start */

/* Joined mode (guarded by s_mux). */
static link_state_t s_link = LINK_OFF;
static bool s_link_wanted;
static int s_join_tries;
static char s_link_ssid[33];
static char s_link_reason[24];
static uint8_t s_link_bssid[6];
static uint32_t s_gw;                      /* gateway for the ICMP keepalive, network order */
static bool s_wifi_ready;                  /* set by the sensing task once Wi-Fi is running */

/* Threat alerts (guarded by s_mux) and chip temperature (guarded by s_mux). */
static thr_slot_t s_thr[THR_SLOTS];
static thr_trk_t s_trk[THR_TRK_SLOTS];     /* tracker first-seen, kept apart from the BLE table */
static thr_ap_ev_t s_apev[AP_TABLE];       /* scratch for ap_choose, under s_mux */
static float s_temp = NAN;
static temperature_sensor_handle_t s_tsens;

static int64_t now_us(void) { return esp_timer_get_time(); }

/* Start of the current channel epoch (M4): untrusted APs may count for THR_BOOTSTRAP_S after it,
 * while nothing is trusted. Reset on every channel change. Guarded by s_mux. */
static int64_t s_trust_epoch_us;
static void trust_epoch(void)
{
    int64_t t = now_us();
    portENTER_CRITICAL(&s_mux);
    s_trust_epoch_us = t;
    portEXIT_CRITICAL(&s_mux);
}

static bool sc_valid(int k, bool skip1) { return k != 0 && !(k >= 27 && k <= 37) && !(skip1 && k == 1); }

/* ---------- Wi-Fi callbacks (wifi task). Short, no logging, no allocation. ---------- */

static int ap_index(const uint8_t *mac)
{
    for (int i = 0; i < AP_TABLE; i++) {
        if (s_ap[i].used && !memcmp(s_ap[i].bssid, mac, 6)) return i;
    }
    return -1;
}

/* Caller holds s_mux. Restores a stored baseline for a re-seen BSSID. Breathing buffers are kept. */
static ap_t *ap_admit(const uint8_t *mac, int64_t now)
{
    /* L4: a new BSSID takes a free slot, else replaces a weak untrusted one (few beacons or gone
     * quiet). Trusted and steady APs are never displaced by a flood of spoofed BSSIDs. */
    for (int i = 0; i < AP_TABLE; i++) {
        s_apev[i] = (thr_ap_ev_t){s_ap[i].used, s_ap[i].trusted, s_ap[i].beacons, s_ap[i].last_seen_us};
    }
    int slot = thr_ap_slot(s_apev, AP_TABLE, now);
    if (slot < 0) return NULL;
    {
        ap_t *a = &s_ap[slot];
        float *bv = a->br_v;
        int64_t *bt = a->br_t;
        uint16_t *bc = a->br_c;
        memset(a, 0, sizeof(*a));
        a->br_v = bv;
        a->br_t = bt;
        a->br_c = bc;
        a->used = true;
        a->learn_start_us = now;
        memcpy(a->bssid, mac, 6);
        for (int k = 0; k < AP_TABLE; k++) {
            if (s_store[k].valid && !memcmp(s_store[k].bssid, mac, 6)) {
                a->base_set = true;
                a->base_rssi = s_store[k].rssi;
                a->base_has_shape = s_store[k].has_shape;
                memcpy(a->base_shape, s_store[k].shape, 64);
            }
        }
        return a;
    }
}

/* Caller holds s_mux. Pushes the current 100 ms bin into the breathing ring. */
static void bin_push(ap_t *a)
{
    int h = a->br_head;
    a->br_v[h] = a->bin_sum / a->bin_n;
    a->br_t[h] = a->bin_t0;
    a->br_c[h] = a->bin_n > 65535 ? 65535 : (uint16_t)a->bin_n;
    a->br_head = (h + 1) % BR_N;
    if (a->br_n < BR_N) a->br_n++;
    a->bin_sum = 0.0f;
    a->bin_n = 0;
}

/* Transmitter BSSID and direction from the 802.11 header. Returns false when the header does
 * not say; the caller then falls back to the CSI source MAC. */
static bool frame_bssid(const uint8_t *h, uint8_t *bssid, bool *uplink)
{
    *uplink = false;
    if (!h) return false;
    int type = (h[0] >> 2) & 3;
    if (type == 0) {                       /* management: addr3 is the BSSID */
        memcpy(bssid, h + 16, 6);
        return true;
    }
    if (type != 2) return false;           /* control frames carry no BSSID here */
    bool tods = h[1] & 1, fromds = h[1] & 2;
    if (tods && !fromds) {                 /* station -> AP: addr1 is the BSSID */
        memcpy(bssid, h + 4, 6);
        *uplink = true;
        return true;
    }
    if (fromds && !tods) {                 /* AP -> station: addr2 is the BSSID */
        memcpy(bssid, h + 10, 6);
        return true;
    }
    return false;
}

#if CONFIG_DEV_BACKDOOR
/* Raw capture ring (development only), allocated in PSRAM by the first sensing_raw_read. */
#define RAW_RING 4096                       /* ~100 s at 40 frames/s */
static portMUX_TYPE s_raw_mux = portMUX_INITIALIZER_UNLOCKED;
static sensing_raw_t *s_raw;
static uint32_t s_raw_w, s_raw_r, s_raw_drop; /* free-running indices, guarded by s_raw_mux */

static void raw_push(const wifi_csi_info_t *info, const uint8_t *bssid, bool uplink)
{
    if (!s_raw) return;
    sensing_raw_t r = {
        .t_us = info->rx_ctrl.timestamp, .rssi = info->rx_ctrl.rssi, .noise_floor = info->rx_ctrl.noise_floor,
        .rate = info->rx_ctrl.rate, .sig_mode = info->rx_ctrl.sig_mode, .mcs = info->rx_ctrl.mcs,
        .cwb = info->rx_ctrl.cwb, .channel = info->rx_ctrl.channel, .sig_len = info->rx_ctrl.sig_len,
        .flags = (uplink ? 1 : 0) | (info->first_word_invalid ? 2 : 0) | (info->rx_ctrl.aggregation ? 4 : 0),
        .fc = info->hdr ? (uint16_t)(info->hdr[0] | info->hdr[1] << 8) : 0,
    };
    memcpy(r.bssid, bssid, 6);
    memcpy(r.dmac, info->dmac, 6);
    memcpy(r.iq, info->buf, 128);
    portENTER_CRITICAL(&s_raw_mux);
    if (s_raw_w - s_raw_r < RAW_RING) s_raw[s_raw_w++ % RAW_RING] = r;
    else s_raw_drop++;
    portEXIT_CRITICAL(&s_raw_mux);
}

size_t sensing_raw_read(sensing_raw_t *out, size_t max, uint32_t *dropped)
{
    if (!s_raw) {
        sensing_raw_t *p = heap_caps_calloc(RAW_RING, sizeof(sensing_raw_t), MALLOC_CAP_SPIRAM);
        portENTER_CRITICAL(&s_raw_mux);
        s_raw = p;
        portEXIT_CRITICAL(&s_raw_mux);
    }
    size_t n = 0;
    portENTER_CRITICAL(&s_raw_mux);
    while (n < max && s_raw_r != s_raw_w) out[n++] = s_raw[s_raw_r++ % RAW_RING];
    *dropped = s_raw_drop;
    s_raw_drop = 0;
    portEXIT_CRITICAL(&s_raw_mux);
    return n;
}
#endif

static void csi_cb(void *ctx, wifi_csi_info_t *info)
{
    (void)ctx;
    if (!info || !info->buf || info->len < 128) return;

    uint8_t bssid[6];
    bool uplink;
    if (!frame_bssid(info->hdr, bssid, &uplink)) {
        memcpy(bssid, info->mac, 6);
        uplink = false;
    }
#if CONFIG_DEV_BACKDOOR
    raw_push(info, bssid, uplink);
#endif
    uint8_t sig = info->rx_ctrl.sig_mode;
    uint8_t rate = info->rx_ctrl.rate;

    /* Lookup and counters first: unattributed and uplink frames stop here. */
    portENTER_CRITICAL(&s_mux);
    s_csi_total++;
    s_hist_sig[sig & 3]++;
    s_hist_rate[rate & 31]++;
    int idx = ap_index(bssid);
    if (idx < 0) s_csi_unattr++;
    else if (uplink) { s_ap[idx].csi_ul++; s_csi_ul_total++; }
    portEXIT_CRITICAL(&s_mux);
    if (idx < 0 || uplink) return;

    /* Downlink for a known AP: normalise and compute the PDP outside the lock. */
    const int8_t *iq = info->buf;     /* imag, real pairs for 64 LLTF subcarriers */
    bool skip1 = info->first_word_invalid;
    float amp[64], norm[64];
    float sum = 0.0f;
    int used = 0;
    for (int i = 0; i < 64; i++) {
        float im = iq[2 * i], re = iq[2 * i + 1];
        amp[i] = sqrtf(re * re + im * im);
        if (!sc_valid(i, skip1)) continue;
        sum += amp[i];
        used++;
    }
    float mean = used ? sum / used : 0.0f;
    for (int i = 0; i < 64; i++) {
        norm[i] = (mean > 0.0f && sc_valid(i, skip1)) ? amp[i] / mean : 0.0f;
    }
    float pdp[16], pmax = 0.0f;
    for (int t = 0; t < 16; t++) {
        float sr = 0.0f, si = 0.0f;
        for (int k = 1; k < 64; k++) {
            if (!sc_valid(k, skip1)) continue;
            float re = iq[2 * k + 1], im = iq[2 * k];
            sr += re * s_cos[k][t] - im * s_sin[k][t];
            si += re * s_sin[k][t] + im * s_cos[k][t];
        }
        pdp[t] = sqrtf(sr * sr + si * si);
        if (pdp[t] > pmax) pmax = pdp[t];
    }
    uint8_t pdp8[16], csi8[64];
    for (int t = 0; t < 16; t++) pdp8[t] = pmax > 0.0f ? (uint8_t)(255.0f * pdp[t] / pmax) : 0;
    for (int k = 0; k < 64; k++) {
        float v = norm[k] * 128.0f;
        csi8[k] = v > 255.0f ? 255 : (uint8_t)v;
    }

    int64_t t = now_us();
    portENTER_CRITICAL(&s_mux);
    ap_t *a = &s_ap[idx];
    if (a->used && !memcmp(a->bssid, bssid, 6)) {
        a->csi_dl++;
        a->last_seen_us = t;
        /* Time-weighted EWMA: alpha depends on the real gap since the last sample. */
        float alpha = 1.0f;
        if (a->ewma_n > 0) {
            alpha = 1.0f - expf(-(float)(t - a->ewma_t) / (CSI_TAU_S * 1e6f));
            if (alpha > 1.0f) alpha = 1.0f;
        }
        for (int k = 0; k < 64; k++) {
            if (!sc_valid(k, skip1)) continue;
            if (a->ewma_n == 0) {
                a->mu[k] = norm[k];
                a->var[k] = 0.0f;
            } else {
                float d = norm[k] - a->mu[k];
                a->mu[k] += alpha * d;
                a->var[k] = (1.0f - alpha) * (a->var[k] + alpha * d * d);
            }
        }
        if (a->ewma_n < 0x40000000) a->ewma_n++;
        a->ewma_t = t;
        memcpy(a->pdp_disp, pdp8, 16);
        memcpy(a->csi_disp, csi8, 64);
        if (a->bin_n == 0) a->bin_t0 = t;
        a->bin_sum += mean;
        a->bin_n++;
        if (t - a->bin_t0 >= BR_BIN_US) bin_push(a);
    }
    portEXIT_CRITICAL(&s_mux);
}

/* Beacon SSID (IE 0) into out, and whether the AP advertises security (capability privacy
 * bit, RSN IE 48, or WPA vendor IE). Done outside the lock. Caller ensures len >= 36. */
static bool beacon_parse(const uint8_t *f, int len, char *out)
{
    bool prot = (f[34] & 0x10) != 0;        /* capability info, low byte, bit 4 = Privacy */
    bool have_ssid = false;
    out[0] = 0;
    int end = len > 4 ? len - 4 : len;      /* drop FCS */
    int pos = 36;                           /* after the 24-byte header and 12 fixed bytes */
    while (pos + 2 <= end) {
        int id = f[pos], l = f[pos + 1];
        if (pos + 2 + l > end) break;
        if (id == 0 && !have_ssid) {
            int n = l <= 32 ? l : 32;
            memcpy(out, f + pos + 2, n);
            out[n] = 0;
            have_ssid = true;
        } else if (id == 48) {
            prot = true;
        } else if (id == 221 && l >= 4 && f[pos + 2] == 0x00 && f[pos + 3] == 0x50 && f[pos + 4] == 0xF2) {
            prot = true;                    /* WPA1 */
        }
        pos += 2 + l;
    }
    return prot;
}

static void promisc_cb(void *buf, wifi_promiscuous_pkt_type_t type)
{
    if (type != WIFI_PKT_MGMT) return;
    const wifi_promiscuous_pkt_t *p = buf;
    const uint8_t *f = p->payload;
    int len = p->rx_ctrl.sig_len;
    if (len < 24) return;
    int subtype = (f[0] >> 4) & 0x0F;
    if (subtype == 0x0C || subtype == 0x0A) {       /* deauth, disassoc: addr3 = BSSID */
        int64_t t = now_us();
        portENTER_CRITICAL(&s_mux);
        int ki = ap_index(f + 16);
        thr_deauth_frame(s_thr, f + 16, t, ki >= 0 && s_ap[ki].trusted);
        portEXIT_CRITICAL(&s_mux);
        return;
    }
    if (len < 36 || (f[0] & 0xFC) != 0x80) return;   /* beacons only */

    char ssid[33];
    bool prot = beacon_parse(f, len, ssid);
    int8_t rssi = p->rx_ctrl.rssi;
    int64_t t = now_us();
    /* Beacon arrival time for the TSF check: rx_ctrl.timestamp is a 32-bit us count taken at
     * reception. Used only when its offset from now is plausible (0..100 ms of callback latency). */
    uint32_t lat = (uint32_t)t - (uint32_t)p->rx_ctrl.timestamp;
    int64_t t_rx = lat < 100000 ? t - (int64_t)lat : t;
    uint16_t seq = (uint16_t)((f[22] | (f[23] << 8)) >> 4);
    uint64_t tsf = 0;
    for (int i = 7; i >= 0; i--) tsf = (tsf << 8) | f[24 + i];

    portENTER_CRITICAL(&s_mux);
    s_beacon_total++;
    ap_t *a = NULL;
    int idx = ap_index(f + 10);                      /* addr2 = BSSID */
    if (idx >= 0) a = &s_ap[idx];
    else a = ap_admit(f + 10, t);
    if (a) {
        if (a->beacons && t - a->last_seen_us > (int64_t)THR_LEARN_GAP_S * 1000000) a->learn_start_us = t;
        a->spoof = thr_beacon(&a->bcn, seq, tsf, t_rx);
        if (a->spoof) a->learn_start_us = t;         /* a spoofed stream never becomes learned */
        a->beacons++;
        a->last_seen_us = t;
        a->rssi = rssi;
        a->ch = p->rx_ctrl.channel;
        a->prot = prot;
        if (!a->ssid[0]) memcpy(a->ssid, ssid, sizeof(a->ssid));
        a->rssi_s[a->rssi_head] = rssi;
        a->rssi_t[a->rssi_head] = t;
        a->rssi_head = (a->rssi_head + 1) % RSSI_RING;
        if (a->rssi_n < RSSI_RING) a->rssi_n++;
        if (s_cal_active) {
            a->cap_sum += rssi;
            a->cap_n++;
        }
    }
    portEXIT_CRITICAL(&s_mux);
}

/* ---------- Joined mode: Wi-Fi station events (system event task) ---------- */

static void reason_str(uint8_t r, char *out, size_t n)
{
    switch (r) {
    case 201: snprintf(out, n, "no_ap"); break;
    case 202: snprintf(out, n, "auth_fail"); break;
    case 15:
    case 204: snprintf(out, n, "handshake_timeout"); break;
    default: snprintf(out, n, "reason_%u", (unsigned)r); break;
    }
}

static void wifi_evt(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    (void)arg;
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        const wifi_event_sta_disconnected_t *d = data;
        bool retry = false, failed = false;
        portENTER_CRITICAL(&s_mux);
        s_gw = 0;
        if (s_link_wanted && s_join_tries < JOIN_TRIES) {
            s_join_tries++;
            s_link = LINK_CONNECTING;
            retry = true;
        } else if (s_link_wanted) {
            s_link_wanted = false;
            s_link = LINK_FAILED;
            failed = true;
        }
        portEXIT_CRITICAL(&s_mux);
        if (retry) {
            esp_wifi_connect();
        } else if (failed) {
            char r[24];
            reason_str(d->reason, r, sizeof(r));
            portENTER_CRITICAL(&s_mux);
            memcpy(s_link_reason, r, sizeof(r));
            portEXIT_CRITICAL(&s_mux);
            esp_wifi_set_channel(s_passive_ch, WIFI_SECOND_CHAN_NONE);   /* back to passive */
            trust_epoch();   /* M4: new channel, new AP set: restart the bootstrap window */
            ESP_LOGW(TAG, "join failed: %s", r);
        }
    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        const ip_event_got_ip_t *e = data;
        /* H1: a lease on (or routing into) 192.168.7.0/24 would let the Wi-Fi network reach the
         * dashboard address. Refuse the network: disconnect and report the failure. */
        uint8_t ip[4], mask[4], gw[4];
        memcpy(ip, &e->ip_info.ip.addr, 4);
        memcpy(mask, &e->ip_info.netmask.addr, 4);
        memcpy(gw, &e->ip_info.gw.addr, 4);
        if (net_policy_lease_conflicts(ip, mask, gw)) {
            portENTER_CRITICAL(&s_mux);
            s_link_wanted = false;                   /* the disconnect event must not retry */
            s_link = LINK_FAILED;
            s_gw = 0;
            snprintf(s_link_reason, sizeof(s_link_reason), "address conflict");
            portEXIT_CRITICAL(&s_mux);
            esp_wifi_disconnect();
            esp_wifi_set_channel(s_passive_ch, WIFI_SECOND_CHAN_NONE);
            trust_epoch();   /* M4: new channel, new AP set: restart the bootstrap window */
            ESP_LOGW(TAG, "join refused: lease overlaps the USB link 192.168.7.0/24");
            return;
        }
        wifi_ap_record_t ap;
        bool have_ap = esp_wifi_sta_get_ap_info(&ap) == ESP_OK;
        portENTER_CRITICAL(&s_mux);
        s_link = LINK_CONNECTED;
        s_join_tries = 0;
        s_gw = e->ip_info.gw.addr;
        if (have_ap) {
            memcpy(s_link_bssid, ap.bssid, 6);
            s_channel = ap.primary;
        }
        portEXIT_CRITICAL(&s_mux);
        ESP_LOGI(TAG, "joined: channel %u", have_ap ? (unsigned)ap.primary : 0u);
    }
}

/* 20 Hz ICMP echo to the joined gateway: the AP's replies are steady OFDM frames for CSI.
 * Raw ICMP socket, replies drained and discarded. Idle (sleeps) when not joined. */
static void ping_task(void *arg)
{
    (void)arg;
    int sock = -1;
    uint16_t seq = 0;
    for (;;) {
        vTaskDelay(pdMS_TO_TICKS(PING_PERIOD_MS));
        portENTER_CRITICAL(&s_mux);
        uint32_t gw = s_gw;
        portEXIT_CRITICAL(&s_mux);
        if (!gw) {
            if (sock >= 0) { close(sock); sock = -1; }
            continue;
        }
        if (sock < 0) {
            sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
            if (sock < 0) {
                ESP_LOGW(TAG, "icmp raw socket failed: errno %d", errno);
                vTaskDelay(pdMS_TO_TICKS(1000));
                continue;
            }
        }
        uint8_t pkt[16] = {0};
        pkt[0] = 8;                              /* echo request */
        pkt[4] = 0x53; pkt[5] = 0x33;            /* identifier */
        pkt[6] = seq >> 8; pkt[7] = seq & 0xff;
        seq++;
        for (int i = 8; i < 16; i++) pkt[i] = (uint8_t)i;
        uint32_t sum = 0;
        for (int i = 0; i < 16; i += 2) sum += ((uint32_t)pkt[i] << 8) | pkt[i + 1];
        while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
        uint16_t cs = (uint16_t)~sum;
        pkt[2] = cs >> 8;
        pkt[3] = cs & 0xff;
        struct sockaddr_in dst = {0};
        dst.sin_family = AF_INET;
        dst.sin_addr.s_addr = gw;
        int sent = sendto(sock, pkt, sizeof(pkt), MSG_DONTWAIT, (struct sockaddr *)&dst, sizeof(dst));
        uint8_t rx[128];
        uint32_t got = 0;
        int r;
        while ((r = recv(sock, rx, sizeof(rx), MSG_DONTWAIT)) > 0) {
            int ihl = (rx[0] & 0x0f) * 4;           /* raw socket: IP header first */
            if (r > ihl && rx[ihl] == 0) got++;     /* ICMP echo reply */
        }
        portENTER_CRITICAL(&s_mux);
        if (sent > 0) s_ping_tx++;
        s_ping_rx += got;
        portEXIT_CRITICAL(&s_mux);
    }
}

/* ---------- BLE observer (NimBLE host task) ---------- */

/* Apple Find My adverts counted by (length byte, status byte) for the 60 s log line, so the
 * raw values on air can be read back. Guarded by s_mux. */
typedef struct { uint8_t len, st; uint16_t n; } a12_cnt_t;
static a12_cnt_t s_a12[12];
static uint8_t s_a12_n;
/* ponytail: 12 buckets, extra (length, status) pairs are dropped; add when more variety shows. */

/* Caller holds s_mux. */
static void apple12_note(uint8_t len, uint8_t st)
{
    for (int i = 0; i < s_a12_n; i++) {
        if (s_a12[i].len == len && s_a12[i].st == st) {
            if (s_a12[i].n < UINT16_MAX) s_a12[i].n++;
            return;
        }
    }
    if (s_a12_n < 12) s_a12[s_a12_n++] = (a12_cnt_t){len, st, 1};
}

static void apple12_log(void)
{
    a12_cnt_t c[12];
    uint8_t n;
    portENTER_CRITICAL(&s_mux);
    n = s_a12_n;
    memcpy(c, s_a12, sizeof(c));
    portEXIT_CRITICAL(&s_mux);
    for (int i = 0; i < n; i++)
        ESP_LOGI(TAG, "apple 0x12 advert len=0x%02x status=0x%02x n=%u", c[i].len, c[i].st, c[i].n);
}

static int ble_gap_cb(struct ble_gap_event *ev, void *arg)
{
    (void)arg;
    if (ev->type != BLE_GAP_EVENT_DISC) return 0;
    const struct ble_gap_disc_desc *d = &ev->disc;
    char name[25] = {0};
    struct ble_hs_adv_fields f;
    if (ble_hs_adv_parse_fields(&f, d->data, d->length_data) == 0 && f.name && f.name_len) {
        int n = f.name_len < 24 ? f.name_len : 24;
        memcpy(name, f.name, n);
        name[n] = 0;
    }
    int64_t t = now_us();
    uint8_t kind = (uint8_t)thr_ble_kind(d->data, d->length_data);
    uint8_t a12_len = 0, a12_st = 0;
    bool a12 = thr_apple12(d->data, d->length_data, &a12_len, &a12_st);

    portENTER_CRITICAL(&s_mux);
    if (a12) apple12_note(a12_len, a12_st);
    ble_t *e = NULL;
    for (int i = 0; i < BLE_TABLE; i++) {
        if (s_ble[i].used && !memcmp(s_ble[i].addr, d->addr.val, 6)) { e = &s_ble[i]; break; }
    }
    if (e) {
        if (t - e->last_us > (int64_t)THR_TRACKER_GAP_S * 1000000) e->first_us = t;
    } else {
        for (int i = 0; i < BLE_TABLE && !e; i++) if (!s_ble[i].used) e = &s_ble[i];
        /* Full: evict the least recently seen ordinary device. Trackers are never evicted by
         * ordinary adverts; a tracker may only displace the least recent tracker. */
        for (int i = 0; i < BLE_TABLE && !e; i++) {
            if (s_ble[i].kind) continue;
            if (!e || s_ble[i].last_us < e->last_us) e = &s_ble[i];
        }
        if (!e && kind) {
            e = &s_ble[0];
            for (int i = 1; i < BLE_TABLE; i++) if (s_ble[i].last_us < e->last_us) e = &s_ble[i];
        }
        if (e) {
            e->used = true;
            memcpy(e->addr, d->addr.val, 6);
            e->name[0] = 0;
            e->rssi = d->rssi;
            e->first_us = t;
            e->kind = 0;
        }
    }
    if (e) {
        e->rssi = 0.7f * e->rssi + 0.3f * d->rssi;
        e->last_us = t;
        if (kind) e->kind = kind;
        if (name[0]) memcpy(e->name, name, sizeof(e->name));
    }
    uint8_t tk = kind ? kind : (e ? e->kind : 0);
    if (tk) thr_trk_seen(s_trk, d->addr.val, tk, t);   /* L4: survives BLE table churn */
    portEXIT_CRITICAL(&s_mux);
    return 0;
}

static void ble_on_sync(void)
{
    uint8_t own;
    if (ble_hs_id_infer_auto(0, &own) != 0) {
        ESP_LOGE(TAG, "ble: no address");
        return;
    }
    struct ble_gap_disc_params p = {0};
    p.passive = 1;                 /* never sends SCAN_REQ */
    p.filter_duplicates = 0;
    p.itvl = BLE_SCAN_ITVL;
    p.window = BLE_SCAN_WIN;
    int rc = ble_gap_disc(own, BLE_HS_FOREVER, &p, ble_gap_cb, NULL);
    ESP_LOGI(TAG, "ble passive observer started rc=%d", rc);
}

static void ble_host_task(void *arg)
{
    (void)arg;
    nimble_port_run();
    vTaskDelete(NULL);
}

static void ble_start(void)
{
    esp_err_t err = nimble_port_init();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nimble init failed: %s", esp_err_to_name(err));
        return;
    }
    ble_hs_cfg.sync_cb = ble_on_sync;
    nimble_port_freertos_init(ble_host_task);
}

/* ---------- NVS: baseline store and Wi-Fi credentials ---------- */

static void store_load(void)
{
    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READONLY, &h) != ESP_OK) return;
    base_blob_t b;
    size_t len = sizeof(b);
    if (nvs_get_blob(h, NVS_BASE_KEY, &b, &len) == ESP_OK && len == sizeof(b) && b.magic == BASE_MAGIC) {
        for (uint32_t i = 0; i < b.n && i < AP_TABLE; i++) s_store[i] = b.e[i];
    }
    nvs_close(h);
}

static void store_save(const base_entry_t *e)
{
    base_blob_t b = {.magic = BASE_MAGIC, .n = 0};
    for (int i = 0; i < AP_TABLE; i++) {
        if (e[i].valid) b.e[b.n++] = e[i];
    }
    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READWRITE, &h) != ESP_OK) return;
    if (nvs_set_blob(h, NVS_BASE_KEY, &b, sizeof(b)) == ESP_OK) nvs_commit(h);
    nvs_close(h);
}

static void wifi_creds_save(const char *ssid, const char *pass)
{
    nvs_handle_t h;
    if (nvs_open(NVS_WIFI_NS, NVS_READWRITE, &h) != ESP_OK) return;
    nvs_set_str(h, "ssid", ssid);
    nvs_set_str(h, "pass", pass);
    nvs_commit(h);
    nvs_close(h);
}

static bool wifi_creds_load(char *ssid, size_t sn, char *pass, size_t pn)
{
    nvs_handle_t h;
    if (nvs_open(NVS_WIFI_NS, NVS_READONLY, &h) != ESP_OK) return false;
    bool ok = nvs_get_str(h, "ssid", ssid, &sn) == ESP_OK && ssid[0] != 0;
    if (ok && nvs_get_str(h, "pass", pass, &pn) != ESP_OK) pass[0] = 0;
    nvs_close(h);
    return ok;
}

static void wifi_creds_erase(void)
{
    nvs_handle_t h;
    if (nvs_open(NVS_WIFI_NS, NVS_READWRITE, &h) != ESP_OK) return;
    nvs_erase_all(h);
    nvs_commit(h);
    nvs_close(h);
}

/* ---------- Wi-Fi bring-up and channel choice ---------- */

/* Passive scan only (no probe requests). Picks the channel with the most RSSI weight. */
static uint8_t pick_channel(void)
{
    int cfg_ch = config_get()->channel;
    wifi_scan_config_t sc = {
        .show_hidden = true,
        .scan_type = WIFI_SCAN_TYPE_PASSIVE,
        .scan_time.passive = 120,
    };
    if (esp_wifi_scan_start(&sc, true) != ESP_OK) return cfg_ch ? cfg_ch : 6;
    uint16_t n = 0;
    esp_wifi_scan_get_ap_num(&n);
    wifi_ap_record_t *recs = calloc(n ? n : 1, sizeof(*recs));
    uint16_t got = n;
    if (recs && n) esp_wifi_scan_get_ap_records(&got, recs);
    int score[15] = {0};
    for (int i = 0; recs && i < got; i++) {
        int c = recs[i].primary;
        if (c >= 1 && c <= 13) score[c] += recs[i].rssi + 100;
    }
    int best = 6, best_score = -1;
    for (int c = 1; c <= 13; c++) if (score[c] > best_score) { best_score = score[c]; best = c; }
    ESP_LOGI(TAG, "passive scan: %u APs", (unsigned)got);
    free(recs);
    return cfg_ch ? (uint8_t)cfg_ch : (uint8_t)best;
}

/* Channel re-pick after a beacon collapse. Never called while joined or with a fixed channel. */
static void repick_channel(void)
{
    esp_wifi_set_csi(false);
    esp_wifi_set_promiscuous(false);
    uint8_t ch = pick_channel();
    esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
    trust_epoch();   /* M4: new channel, new AP set: restart the bootstrap window */
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_csi(true);
    portENTER_CRITICAL(&s_mux);
    s_channel = ch;
    s_passive_ch = ch;
    portEXIT_CRITICAL(&s_mux);
    ESP_LOGI(TAG, "beacon rate collapsed: rescanned, channel %d", ch);
}

/* ---------- 10 Hz tick (sensing task) ---------- */

static float clampf(float x, float lo, float hi) { return x < lo ? lo : (x > hi ? hi : x); }

/* Motion from a short RSSI window: sample std in dB above the quantisation floor. */
static float rssi_motion(const ap_t *a, int64_t now)
{
    double s = 0, s2 = 0;
    int n = 0;
    for (int i = 0; i < a->rssi_n; i++) {
        if (now - a->rssi_t[i] > RSSI_WIN_US) continue;
        s += a->rssi_s[i];
        s2 += (double)a->rssi_s[i] * a->rssi_s[i];
        n++;
    }
    if (n < 4) return 0.0f;
    double m = s / n;
    float sd = (float)sqrt(fmax(0.0, s2 / n - m * m));
    return clampf((sd - RSSI_SD_FLOOR) / (RSSI_SD_FULL - RSSI_SD_FLOOR), 0.0f, 1.0f);
}

/* RSSI shift from the captured baseline, scaled to 0..1. -1 when the window has no samples. */
static float rssi_dev(const ap_t *a, int64_t now)
{
    double s = 0;
    int n = 0;
    for (int k = 0; k < a->rssi_n; k++) {
        if (now - a->rssi_t[k] > RSSI_WIN_US) continue;
        s += a->rssi_s[k];
        n++;
    }
    if (!n) return -1.0f;
    return clampf(fabsf((float)(s / n) - a->base_rssi) / BASE_DB_FULL, 0.0f, 1.0f);
}

/* Motion from CSI: mean over subcarriers of the EWMA std of normalised amplitude. */
static float csi_motion(const ap_t *a)
{
    float acc = 0.0f;
    int cnt = 0;
    for (int k = 1; k < 64; k++) {
        if (!sc_valid(k, false)) continue;
        acc += sqrtf(fmaxf(0.0f, a->var[k]));
        cnt++;
    }
    return cnt ? clampf((acc / cnt) / CSI_MOTION_FULL, 0.0f, 1.0f) : 0.0f;
}

/* Baseline deviation from the CSI shape: mean abs difference of the mean amplitude. */
static float shape_dev(const ap_t *a)
{
    float acc = 0.0f;
    int cnt = 0;
    for (int k = 1; k < 64; k++) {
        if (!sc_valid(k, false)) continue;
        acc += fabsf(a->mu[k] - a->base_shape[k] / 128.0f);
        cnt++;
    }
    return cnt ? clampf((acc / cnt) / BASE_SHAPE_FULL, 0.0f, 1.0f) : 0.0f;
}

/* Breathing from the last 30 s of 100 ms bins, resampled to 10 Hz (sample and hold). Runs every 5 s. */
static float s_brv[BR_N];
static int64_t s_brt[BR_N];
static uint16_t s_brc[BR_N];

static void breath_pass(void)
{
    static float x[BR_N];
    for (int i = 0; i < AP_TABLE; i++) {
        portENTER_CRITICAL(&s_mux);
        ap_t *a = &s_ap[i];
        int n = a->used ? a->br_n : 0;
        for (int k = 0; k < n; k++) {
            int idx = (a->br_head + BR_N - n + k) % BR_N;   /* oldest first */
            s_brv[k] = a->br_v[idx];
            s_brt[k] = a->br_t[idx];
            s_brc[k] = a->br_c[idx];
        }
        portEXIT_CRITICAL(&s_mux);

        float bpm = 0.0f, conf = 0.0f;
        bool ok = false;
        int64_t dbg_lead = 0, dbg_gap = 0;
        float dbg_rate = 0.0f;
        if (n >= 2) {
            int64_t t_end = s_brt[n - 1];
            int64_t t_start = t_end - BR_WIN_US;
            int first = 0;
            while (first < n && s_brt[first] < t_start) first++;
            /* Window must reach the present: a dead AP's old bins are not breathing. */
            ok = n - first >= 2 && s_brt[first] <= t_start + BR_GAP_US && now_us() - t_end <= BR_GAP_US;
            uint32_t cnt = 0;
            int64_t maxgap = 0;
            for (int k = first; k < n; k++) {
                cnt += s_brc[k];
                if (k > first && s_brt[k] - s_brt[k - 1] > maxgap) maxgap = s_brt[k] - s_brt[k - 1];
            }
            dbg_lead = s_brt[first] - t_start;
            dbg_gap = maxgap;
            dbg_rate = (float)cnt / ((float)BR_WIN_US / 1e6f);
            ok = ok && maxgap <= BR_GAP_US;
            ok = ok && dbg_rate >= BR_MIN_FPS;
            if (ok) {
                /* Holes up to BR_GAP_US are bridged by linear interpolation. */
                dsp_resample(s_brv + first, s_brt + first, n - first, t_start, BR_BIN_US, x, BR_N);
                ok = dsp_breath_estimate(x, BR_N, 10.0f, &bpm, &conf);
            }
        }
        if (!ok) { bpm = 0.0f; conf = 0.0f; }

        portENTER_CRITICAL(&s_mux);
        a->breath_bpm = bpm;
        a->breath_conf = conf;
        portEXIT_CRITICAL(&s_mux);
        if (n >= 2) {
            ESP_LOGI(TAG, "breath slot%d bins=%d gate=%d lead=%.2fs maxgap=%.2fs rate=%.2f bpm=%.1f conf=%.2f",
                     i, n, ok, dbg_lead / 1e6, dbg_gap / 1e6, dbg_rate, bpm, conf);
        }
    }
}

/* Presence, away countdown, baseline capture and rescan decision. Runs every tick under s_mux.
 * Side effects (lock, LED, NVS, Wi-Fi) are returned in the out flags and done outside the lock. */
typedef struct { bool cal_done; bool present; int away_in; bool repick; } tick_out_t;

static void tick_locked(int64_t now, const app_config_t *cfg, tick_out_t *out)
{
    memset(out, 0, sizeof(*out));
    static int64_t s_rate_t, s_low_since, s_last_repick;
    static uint32_t s_beacon_prev;
    if (s_rate_t == 0) {
        s_rate_t = now;
        s_low_since = now;
        s_last_repick = now;
    }
    int64_t sec = now - s_rate_t;
    bool rate_tick = sec >= 1000000;
    if (rate_tick) {
        s_rate_t = now;
        s_beacon_rate = (float)(s_beacon_total - s_beacon_prev) * 1e6f / (float)sec;
        s_beacon_prev = s_beacon_total;
    }

    /* M4 trust: an AP may feed presence only when it is in the baseline, is the joined AP, or
     * has beaconed steadily for THR_LEARN_S; an AP whose beacon stream looks spoofed never does.
     * In the first THR_BOOTSTRAP_S after boot, before anything is trusted, every AP counts so
     * presence works from power-on. */
    bool any_trusted = false;
    bool joined = s_link == LINK_CONNECTED;
    for (int i = 0; i < AP_TABLE; i++) {
        ap_t *a = &s_ap[i];
        if (!a->used) continue;
        a->trusted = a->base_set || (joined && !memcmp(a->bssid, s_link_bssid, 6)) ||
                     thr_ap_learned(a->learn_start_us, now);
        if (a->trusted && !a->spoof) any_trusted = true;
    }

    float motion_max = 0.0f, base_dev = 0.0f;
    for (int i = 0; i < AP_TABLE; i++) {
        ap_t *a = &s_ap[i];
        if (!a->used) continue;
        if (now - a->last_seen_us > AP_AGE_US) {
            a->used = false;
            continue;
        }
        bool counts = thr_ap_counts(a->trusted, a->spoof, any_trusted, now - s_trust_epoch_us);
        if (rate_tick) {
            a->csi_fps = (float)(a->csi_dl - a->csi_prev) * 1e6f / (float)sec;
            a->csi_prev = a->csi_dl;
        }
        bool csi_ok = a->csi_fps >= CSI_MIN_FPS && a->ewma_n >= CSI_WARM;
        a->motion_rssi = rssi_motion(a, now);
        a->motion_csi = csi_ok ? csi_motion(a) : 0.0f;
        a->motion = csi_ok ? a->motion_csi : a->motion_rssi;   /* fused per AP */
        if (!counts) continue;                 /* shown in the frame, never counted */
        if (a->motion > motion_max) motion_max = a->motion;

        if (a->base_set) {
            float dev = (a->base_has_shape && csi_ok) ? shape_dev(a) : rssi_dev(a, now);
            if (dev > base_dev) base_dev = dev;
        }
    }
    s_motion_raw = motion_max;
    s_motion += MOTION_EWMA * (motion_max - s_motion);
    s_base_dev = base_dev;

    for (int i = 0; i < BLE_TABLE; i++) {
        if (s_ble[i].used && now - s_ble[i].last_us > BLE_TTL_US) s_ble[i].used = false;
    }
    thr_trk_tick(s_trk, now);

    /* Baseline capture finishes: captured set replaces the store. */
    if (s_cal_active && now >= s_cal_end_us) {
        s_cal_active = false;
        out->cal_done = true;
    }

    /* Presence. */
    bool motion_ok = s_motion > cfg->motion_threshold;
    bool breath_ok = false;
    if (cfg->use_breathing) {
        for (int i = 0; i < AP_TABLE; i++) {
            const ap_t *a = &s_ap[i];
            if (a->used && a->breath_conf >= BR_CONF_PRESENT &&
                thr_ap_counts(a->trusted, a->spoof, any_trusted, now - s_trust_epoch_us)) breath_ok = true;
        }
    }
    bool base_ok = cfg->use_baseline && s_base_dev >= BASE_DEV_PRESENT;
    const char *why = motion_ok ? "motion" : breath_ok ? "breathing" : base_ok ? "baseline" : NULL;
    if (why) {
        s_last_active_us = now;
        s_why = why;
        s_away_in = -1;
        out->present = true;
    } else {
        s_why = NULL;
        int64_t remain_us = (int64_t)cfg->away_secs * 1000000 - (now - s_last_active_us);
        if (remain_us > 0) {
            s_away_in = (int)((remain_us + 999999) / 1000000);
            out->present = true;
        } else {
            s_away_in = 0;
            out->present = false;
        }
    }
    s_present = out->present;
    out->away_in = s_away_in;

    /* Breathing shown only when motion is low and conf clears the show threshold. */
    s_br_visible = false;
    s_br_bpm = 0; s_br_conf = 0;
    s_br_state = !cfg->use_breathing ? "off" : s_motion > BR_MOTION_MAX ? "motion" : "listening";
    if (cfg->use_breathing && s_motion <= BR_MOTION_MAX) {
        for (int i = 0; i < AP_TABLE; i++) {
            if (!s_ap[i].used) continue;
            if (s_ap[i].breath_conf >= BR_CONF_SHOW && s_ap[i].breath_conf > s_br_conf) {
                s_br_conf = s_ap[i].breath_conf;
                s_br_bpm = s_ap[i].breath_bpm;
                s_br_visible = true;
                s_br_state = "found";
            }
        }
    }

    /* Rescan when the beacon total collapses: at most every 3 min, never while joined, and only
     * on a free channel choice. */
    if (rate_tick && !s_link_wanted && cfg->channel == 0 && !s_cal_active) {
        if (s_beacon_rate >= BEACON_MIN_FPS) {
            s_low_since = now;
        } else if (now - s_low_since >= BEACON_LOW_S * 1000000LL && now - s_last_repick >= REPICK_US) {
            out->repick = true;
            s_last_repick = now;
            s_low_since = now;
        }
    }
}

/* Copies of the baseline store, built under the lock when a capture ends. */
static void capture_finish(void)
{
    base_entry_t e[AP_TABLE];
    memset(e, 0, sizeof(e));
    portENTER_CRITICAL(&s_mux);
    for (int i = 0; i < AP_TABLE; i++) {
        ap_t *a = &s_ap[i];
        if (!a->used || a->cap_n < BASE_MIN_SAMPLES) continue;
        bool csi_ok = a->csi_fps >= CSI_MIN_FPS && a->ewma_n >= CSI_WARM;
        e[i].valid = 1;
        e[i].has_shape = csi_ok;
        memcpy(e[i].bssid, a->bssid, 6);
        e[i].rssi = a->cap_sum / a->cap_n;
        for (int k = 0; k < 64; k++) {
            float q = csi_ok ? a->mu[k] * 128.0f : 0.0f;
            e[i].shape[k] = q < 0.0f ? 0 : (q > 255.0f ? 255 : (uint8_t)q);
        }
        a->base_set = true;
        a->base_rssi = e[i].rssi;
        a->base_has_shape = csi_ok;
        memcpy(a->base_shape, e[i].shape, 64);
    }
    for (int i = 0; i < AP_TABLE; i++) { s_ap[i].cap_n = 0; s_ap[i].cap_sum = 0; }
    portEXIT_CRITICAL(&s_mux);
    int n = 0, shapes = 0;
    for (int i = 0; i < AP_TABLE; i++) { if (e[i].valid) n++; if (e[i].has_shape) shapes++; }
    memcpy(s_store, e, sizeof(e));
    store_save(e);
    ESP_LOGI(TAG, "baseline captured for %d APs (%d with CSI shape)", n, shapes);
}

static void apply_leds(bool present)
{
    if (strcmp(fido_state_str(), "idle") != 0) return;   /* never override FIDO LEDs */
    led_mode_t want = present ? LED_PRESENT : (config_get()->autolock ? LED_LOCKED : LED_AWAY);
    if (led_get_mode() != want) led_set_mode(want);
}

/* Release builds keep per-BSSID counters out of the log ring (they fingerprint the location). */
#if CONFIG_DEV_BACKDOOR
#define STAT_LOG ESP_LOGI
#else
#define STAT_LOG ESP_LOGD
#endif

/* 5 s counters for the log (copied under the lock, logged outside it). */
static void stats_log(void)
{
    uint32_t ct, cu, ul, bc = 0, apd[AP_TABLE], apu[AP_TABLE], apb[AP_TABLE];
    uint32_t sig[4], rate[32], ptx, prx;
    float fps[AP_TABLE];
    uint8_t mac[AP_TABLE][6];
    int n = 0;
    portENTER_CRITICAL(&s_mux);
    ct = s_csi_total;
    ptx = s_ping_tx; prx = s_ping_rx;
    s_ping_tx = s_ping_rx = 0;
    cu = s_csi_unattr;
    ul = s_csi_ul_total;
    memcpy(sig, s_hist_sig, sizeof(sig));
    memcpy(rate, s_hist_rate, sizeof(rate));
    for (int i = 0; i < AP_TABLE; i++) {
        if (!s_ap[i].used) continue;
        bc += s_ap[i].beacons;
        apd[n] = s_ap[i].csi_dl;
        apu[n] = s_ap[i].csi_ul;
        apb[n] = s_ap[i].beacons;
        fps[n] = s_ap[i].csi_fps;
        memcpy(mac[n], s_ap[i].bssid, 6);
        n++;
    }
    portEXIT_CRITICAL(&s_mux);
    STAT_LOG(TAG, "stat csi total=%u attributed=%u unattr=%u uplink=%u beacons=%u aps=%d",
             (unsigned)ct, (unsigned)(ct - cu), (unsigned)cu, (unsigned)ul, (unsigned)bc, n);
    STAT_LOG(TAG, "stat ping tx=%u rx=%u (5 s)", (unsigned)ptx, (unsigned)prx);
    for (int i = 0; i < n; i++) {
        STAT_LOG(TAG, "stat ap %02x%02x%02x%02x%02x%02x dl=%u ul=%u beacons=%u fps=%.2f", mac[i][0], mac[i][1],
                 mac[i][2], mac[i][3], mac[i][4], mac[i][5], (unsigned)apd[i], (unsigned)apu[i],
                 (unsigned)apb[i], fps[i]);
    }
    STAT_LOG(TAG, "stat sig_mode 0=%u 1=%u 3=%u", (unsigned)sig[0], (unsigned)sig[1], (unsigned)sig[3]);
    char line[160];
    int len = snprintf(line, sizeof(line), "stat rate");
    for (int r = 0; r < 32 && len < (int)sizeof(line) - 12; r++) {
        if (rate[r]) len += snprintf(line + len, sizeof(line) - len, " %d:%u", r, (unsigned)rate[r]);
    }
    STAT_LOG(TAG, "%s", line);
}

/* Reads the Wi-Fi join state for the frame, the /api/wifi reply and /api/status. */
void sensing_link_get(sensing_link_t *o)
{
    link_state_t st;
    uint8_t bssid[6];
    char ssid[33], reason[24];
    portENTER_CRITICAL(&s_mux);
    st = s_link;
    memcpy(bssid, s_link_bssid, 6);
    memcpy(ssid, s_link_ssid, sizeof(ssid));
    memcpy(reason, s_link_reason, sizeof(reason));
    float rate = 0.0f;
    if (st == LINK_CONNECTED) {
        int idx = ap_index(bssid);
        if (idx >= 0) rate = s_ap[idx].csi_fps;
    }
    portEXIT_CRITICAL(&s_mux);
    o->state = s_link_names[st];
    o->mode = st == LINK_CONNECTED ? "joined" : "passive";
    o->has_ssid = st != LINK_OFF && ssid[0] != 0;
    memcpy(o->ssid, ssid, sizeof(o->ssid));
    o->has_reason = st == LINK_FAILED && reason[0] != 0;
    memcpy(o->reason, reason, sizeof(o->reason));
    o->rate = rate;
}

static void join_now(const char *ssid, const char *pass)
{
    wifi_config_t wc;
    memset(&wc, 0, sizeof(wc));
    strlcpy((char *)wc.sta.ssid, ssid, sizeof(wc.sta.ssid));
    strlcpy((char *)wc.sta.password, pass, sizeof(wc.sta.password));
    wc.sta.threshold.authmode = pass[0] ? WIFI_AUTH_WPA2_PSK : WIFI_AUTH_OPEN;
    wc.sta.pmf_cfg.capable = true;
    wc.sta.sae_pwe_h2e = WPA3_SAE_PWE_BOTH;
    esp_wifi_disconnect();
    esp_wifi_set_config(WIFI_IF_STA, &wc);
    portENTER_CRITICAL(&s_mux);
    s_link_wanted = true;
    s_join_tries = 0;
    s_link = LINK_CONNECTING;
    snprintf(s_link_ssid, sizeof(s_link_ssid), "%s", ssid);
    s_link_reason[0] = 0;
    s_gw = 0;
    portEXIT_CRITICAL(&s_mux);
    esp_wifi_connect();
    trust_epoch();   /* M4: new channel, new AP set: restart the bootstrap window */
}

esp_err_t sensing_wifi_join(const char *ssid, const char *pass)
{
    if (!s_wifi_ready) return ESP_ERR_INVALID_STATE;
    wifi_creds_save(ssid, pass);
    join_now(ssid, pass);
    return ESP_OK;
}

void sensing_wifi_forget(void)
{
    portENTER_CRITICAL(&s_mux);
    s_link_wanted = false;
    s_link = LINK_OFF;
    s_link_ssid[0] = 0;
    s_link_reason[0] = 0;
    memset(s_link_bssid, 0, sizeof(s_link_bssid));
    s_gw = 0;
    portEXIT_CRITICAL(&s_mux);
    wifi_creds_erase();
    if (s_wifi_ready) {
        esp_wifi_disconnect();
        esp_wifi_set_channel(s_passive_ch, WIFI_SECOND_CHAN_NONE);
        trust_epoch();   /* M4: new channel, new AP set: restart the bootstrap window */
    }
    ESP_LOGI(TAG, "wifi join cleared, passive");
}

static void sensing_task(void *arg)
{
    (void)arg;
    int stat_n = 0;
    /* Station netif for joined mode; the default route it gets never reaches the USB netif. */
    esp_netif_create_default_wifi_sta();
    wifi_init_config_t wcfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&wcfg));
#if !CONFIG_DEV_BACKDOOR
    esp_log_level_set("wifi", ESP_LOG_WARN);   /* driver INFO lines carry BSSIDs and SSIDs */
#endif
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_start());
    uint8_t ch = pick_channel();
    ESP_ERROR_CHECK(esp_wifi_set_ps(WIFI_PS_NONE));
    ESP_ERROR_CHECK(esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE));
    trust_epoch();   /* M4: new channel, new AP set: restart the bootstrap window */
    portENTER_CRITICAL(&s_mux);
    s_channel = ch;
    s_passive_ch = ch;
    portEXIT_CRITICAL(&s_mux);

    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, wifi_evt, NULL, NULL));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP, wifi_evt, NULL, NULL));

    /* Management and data frames: beacons for AP presence, data for CSI. */
    wifi_promiscuous_filter_t filt = {.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA};
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_filter(&filt));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb(promisc_cb));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));

    wifi_csi_config_t csi = {
        .lltf_en = true, .htltf_en = false, .stbc_htltf2_en = false,
        .ltf_merge_en = false, .channel_filter_en = false, .manu_scale = false,
        .shift = 0, .dump_ack_en = false,
    };
    ESP_ERROR_CHECK(esp_wifi_set_csi_config(&csi));
    ESP_ERROR_CHECK(esp_wifi_set_csi_rx_cb(csi_cb, NULL));
    ESP_ERROR_CHECK(esp_wifi_set_csi(true));
    ESP_LOGI(TAG, "promiscuous (mgmt+data) + CSI on channel %d", ch);

    s_wifi_ready = true;
    ble_start();

    temperature_sensor_config_t tcfg = TEMPERATURE_SENSOR_CONFIG_DEFAULT(-10, 80);
    if (temperature_sensor_install(&tcfg, &s_tsens) != ESP_OK || temperature_sensor_enable(s_tsens) != ESP_OK) {
        ESP_LOGE(TAG, "temperature sensor unavailable");
        s_tsens = NULL;
    }

    char ssid[33], pass[65];
    if (wifi_creds_load(ssid, sizeof(ssid), pass, sizeof(pass))) {
        ESP_LOGI(TAG, "joined mode: rejoining saved network");
        join_now(ssid, pass);
    }

    int tmp_n = 0, a12_n = 0;
    lock_policy_t lockp = {0};
    for (;;) {
        vTaskDelay(pdMS_TO_TICKS(TICK_MS));
        int64_t now = now_us();
        const app_config_t *cfg = config_get();
        if (++a12_n >= 600) {                    /* 60 s: Find My raw-value histogram to the log */
            a12_n = 0;
            apple12_log();
        }
        tick_out_t out;
        portENTER_CRITICAL(&s_mux);
        tick_locked(now, cfg, &out);
        thr_tick(s_thr, now);
        portEXIT_CRITICAL(&s_mux);

        if (s_tsens && ++tmp_n >= 10) {          /* chip temperature once a second */
            tmp_n = 0;
            float c;
            if (temperature_sensor_get_celsius(s_tsens, &c) == ESP_OK) {
                portENTER_CRITICAL(&s_mux);
                s_temp = c;
                portEXIT_CRITICAL(&s_mux);
            }
        }

        if (out.cal_done) capture_finish();
        if (out.repick) repick_channel();

        /* M3/L6: one lock per away period, counted only when it reached the host; a failed
         * attempt (keyboard not ready, host asleep) is retried every LOCK_RETRY_US while away.
         * Re-evaluated every tick, so enabling autolock while away locks at once. */
        if (lock_policy_due(&lockp, !out.present, cfg->autolock, now)) {
            bool first = lockp.next_try_us == 0;
            bool ok = lock_send();
            lock_policy_result(&lockp, ok, now);
            if (ok) ESP_LOGW(TAG, "away: autolock sent");
            else if (first) ESP_LOGW(TAG, "away: autolock not delivered (host asleep or keyboard not ready), retrying");
        }
        apply_leds(out.present);

        if (++stat_n >= 50) {       /* breathing at 1 Hz, counters logged every 5 s */
            stat_n = 0;
            breath_pass();
            stats_log();
        }
    }
}

/* ---------- JSON writer: bounded, checkpointed ---------- */

typedef struct { char *b; size_t cap; size_t len; bool ok; } jw_t;

static void jw_raw(jw_t *w, const char *s)
{
    if (!w->ok) return;
    size_t n = strlen(s);
    if (w->len + n + 1 > w->cap) { w->ok = false; return; }
    memcpy(w->b + w->len, s, n);
    w->len += n;
    w->b[w->len] = 0;
}

static void jw_fmt(jw_t *w, const char *fmt, ...)
{
    if (!w->ok) return;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(w->b + w->len, w->cap - w->len, fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= w->cap - w->len) { w->ok = false; w->b[w->len] = 0; return; }
    w->len += n;
}

/* Writes a float with the given decimals. */
static void jw_float(jw_t *w, float v, int decimals)
{
    if (!isfinite(v)) v = 0.0f;
    if (decimals == 1) jw_fmt(w, "%.1f", (double)v);
    else jw_fmt(w, "%.2f", (double)v);
}

/* Quoted, escaped string (thr_json_escape: quotes, backslashes, control bytes; non-ASCII -> '?'). */
static void jw_str(jw_t *w, const char *s)
{
    char e[200];                            /* SSID 32 or name 24 bytes, worst case 6 per byte */
    if (!thr_json_escape(e, sizeof(e), s)) { w->ok = false; return; }
    jw_raw(w, e);
}

static void hex12(char *out, const uint8_t *m)
{
    snprintf(out, 13, "%02x%02x%02x%02x%02x%02x", m[0], m[1], m[2], m[3], m[4], m[5]);
}

static float dist_m(int rssi)
{
    float d = powf(10.0f, (DIST_RSSI_1M - rssi) / (10.0f * DIST_N));
    return clampf(d, 0.1f, 99.9f);
}

/* Display copies, taken under s_mux and formatted outside it. Only the httpd task calls
 * the snapshot, so these statics are not shared between callers. */
typedef struct {
    uint8_t bssid[6];
    char ssid[33];
    uint8_t ch;
    int rssi;
    float motion, rate;
    uint8_t flag;                 /* 0 none, 1 deauth, 2 twin, 3 spoof */
    bool trusted;
    uint8_t csi[64], pdp[16];
} apd_t;
typedef struct {
    uint8_t addr[6];
    char name[25];
    float rssi;
    int64_t first_us;
    uint8_t kind;
} bled_t;
typedef struct {
    uint8_t kind;                 /* thr_kind_t */
    uint8_t trk;                  /* trk_kind_t for trackers */
    uint8_t key[6];
    char label[33];
    int64_t raised_us;
    uint32_t n;                   /* deauth frames in the window */
} alert_t;
#define ALERT_CAP (THR_SLOTS + THR_TRK_SLOTS)

static apd_t s_apd[AP_TABLE];
static bled_t s_bled[BLE_TABLE];
static alert_t s_alerts[ALERT_CAP];
static thr_ap_t s_tap[AP_TABLE];
static bool s_tflag[AP_TABLE];

/* Caller holds s_mux, and s_tap[0..na) and s_apd[0..na) are filled. Sets the per-AP flag, keeps
 * the evil-twin slots current, and collects the alerts (newest first) into s_alerts. */
static int threats_locked(int na, int64_t now)
{
    thr_twin_flags(s_tap, na, s_tflag);
    for (int i = 0; i < na; i++) {
        int ai = ap_index(s_tap[i].bssid);
        thr_twin_set(s_thr, s_tap[i].bssid, s_tflag[i], now, ai >= 0 && s_ap[ai].trusted);
        const thr_slot_t *dv = thr_find(s_thr, THR_DEAUTH, s_tap[i].bssid);
        s_apd[i].flag = (dv && dv->active) ? 1 : (s_tflag[i] ? 2 : (ai >= 0 && s_ap[ai].spoof ? 3 : 0));
    }
    int nal = 0;
    for (int i = 0; i < THR_SLOTS && nal < ALERT_CAP; i++) {
        const thr_slot_t *s = &s_thr[i];
        if (!s->used || !s->active) continue;
        alert_t *al = &s_alerts[nal++];
        al->kind = s->kind;
        al->trk = TRK_NONE;
        memcpy(al->key, s->key, 6);
        al->raised_us = s->raised_us;
        al->n = s->kind == THR_DEAUTH ? thr_deauth_count(s, now) : 0;
        int ai = ap_index(s->key);
        if (ai >= 0) memcpy(al->label, s_ap[ai].ssid, sizeof(al->label));
        else al->label[0] = 0;
    }
    for (int i = 0; i < THR_TRK_SLOTS && nal < ALERT_CAP; i++) {
        const thr_trk_t *k = &s_trk[i];
        if (!k->used || !thr_tracker_alert(k->first_us, k->last_us, now)) continue;
        alert_t *al = &s_alerts[nal++];
        al->kind = THR_TRACKER;
        al->trk = k->kind;
        memcpy(al->key, k->addr, 6);
        al->raised_us = k->first_us + (int64_t)THR_TRACKER_ALERT_S * 1000000;
        al->n = 0;
        memset(al->label, 0, sizeof(al->label));
        for (int j = 0; j < BLE_TABLE; j++) {
            if (s_ble[j].used && !memcmp(s_ble[j].addr, k->addr, 6)) memcpy(al->label, s_ble[j].name, sizeof(s_ble[j].name));
        }
    }
    for (int i = 1; i < nal; i++) {
        alert_t t = s_alerts[i];
        int j = i - 1;
        while (j >= 0 && s_alerts[j].raised_us < t.raised_us) { s_alerts[j + 1] = s_alerts[j]; j--; }
        s_alerts[j + 1] = t;
    }
    return nal;
}

size_t sensing_snapshot_json(char *buf, size_t len)
{
    if (!buf || len < 64) return 0;
    if (s_fault) {
        int n = snprintf(buf, len, "{\"t\":%lld,\"ch\":0,\"motion\":0,\"presence\":\"present\","
                         "\"away_in\":null,\"why\":null,\"breath\":null,\"baseline\":null,"
                         "\"aps\":[],\"ble\":[],\"alerts\":[],"
                         "\"link\":{\"mode\":\"passive\",\"state\":\"off\",\"ssid\":null},"
                         "\"fido\":{\"state\":\"%s\"},\"stub\":true,\"fault\":\"%s\"}",
                         (long long)(now_us() / 1000), fido_state_str(), s_fault);
        return n > 0 && (size_t)n < len ? (size_t)n : 0;
    }
    int na = 0, nb = 0, nal = 0;
    int64_t now = now_us();
    bool present; int away_in; const char *why; float motion;
    bool br_vis; float br_bpm, br_conf; const char *br_state;
    float base_dev; bool cal_active; int cal_left;
    bool any_base;

    sensing_link_t link;
    sensing_link_get(&link);

    portENTER_CRITICAL(&s_mux);
    for (int i = 0; i < AP_TABLE; i++) {
        const ap_t *a = &s_ap[i];
        if (!a->used) continue;
        apd_t *d = &s_apd[na++];
        memcpy(d->bssid, a->bssid, 6);
        memcpy(d->ssid, a->ssid, sizeof(d->ssid));
        d->ch = a->ch;
        d->rssi = a->rssi;
        d->motion = a->motion;
        d->rate = a->csi_fps;
        d->trusted = a->trusted && !a->spoof;
        memcpy(d->csi, a->csi_disp, 64);
        memcpy(d->pdp, a->pdp_disp, 16);
        memcpy(s_tap[na - 1].bssid, a->bssid, 6);
        memcpy(s_tap[na - 1].ssid, a->ssid, sizeof(s_tap[0].ssid));
        s_tap[na - 1].open = !a->prot;
    }
    for (int i = 0; i < BLE_TABLE; i++) {
        if (!s_ble[i].used) continue;
        bled_t *d = &s_bled[nb++];
        memcpy(d->addr, s_ble[i].addr, 6);
        memcpy(d->name, s_ble[i].name, sizeof(d->name));
        d->rssi = s_ble[i].rssi;
        d->first_us = s_ble[i].first_us;
        d->kind = s_ble[i].kind;
        for (int k = 0; k < THR_TRK_SLOTS; k++) {
            if (s_trk[k].used && !memcmp(s_trk[k].addr, d->addr, 6)) d->first_us = s_trk[k].first_us;
        }
    }
    present = s_present; away_in = s_away_in; why = s_why; motion = s_motion;
    br_vis = s_br_visible; br_bpm = s_br_bpm; br_conf = s_br_conf; br_state = s_br_state;
    base_dev = s_base_dev; cal_active = s_cal_active;
    cal_left = cal_active ? (int)((s_cal_end_us - now) / 1000000) + 1 : 0;
    any_base = false;
    for (int i = 0; i < AP_TABLE; i++) if (s_ap[i].used && s_ap[i].base_set) any_base = true;
    nal = threats_locked(na, now);
    portEXIT_CRITICAL(&s_mux);

    /* strongest first */
    for (int i = 1; i < na; i++) {
        apd_t t = s_apd[i];
        int j = i - 1;
        while (j >= 0 && s_apd[j].rssi < t.rssi) { s_apd[j + 1] = s_apd[j]; j--; }
        s_apd[j + 1] = t;
    }
    if (na > AP_OUT) na = AP_OUT;

    jw_t w = {.b = buf, .cap = len, .len = 0, .ok = true};
    buf[0] = 0;
    jw_fmt(&w, "{\"t\":%lld,\"ch\":%u,\"motion\":", (long long)(now / 1000), (unsigned)s_channel);
    jw_float(&w, motion, 2);
    jw_fmt(&w, ",\"presence\":\"%s\",\"away_in\":", present ? "present" : "away");
    if (away_in >= 0) jw_fmt(&w, "%d", away_in);
    else jw_raw(&w, "null");
    jw_raw(&w, ",\"why\":");
    if (why) jw_str(&w, why); else jw_raw(&w, "null");

    jw_raw(&w, ",\"breath\":");
    if (br_vis) {
        jw_raw(&w, "{\"bpm\":");
        jw_float(&w, br_bpm, 1);
        jw_raw(&w, ",\"conf\":");
        jw_float(&w, br_conf, 2);
        jw_raw(&w, "}");
    } else {
        jw_raw(&w, "null");
    }
    jw_raw(&w, ",\"breath_state\":");
    jw_str(&w, br_state);

    jw_raw(&w, ",\"baseline\":");
    if (cal_active) {
        jw_fmt(&w, "{\"set\":false,\"capturing\":true,\"left\":%d}", cal_left);
    } else {
        jw_fmt(&w, "{\"set\":%s,\"dev\":", any_base ? "true" : "false");
        jw_float(&w, base_dev, 2);
        jw_raw(&w, "}");
    }

    jw_raw(&w, ",\"aps\":[");
    int emitted = 0;
    for (int i = 0; i < na && w.ok; i++) {
        const apd_t *d = &s_apd[i];
        size_t mark = w.len;
        bool mark_ok = w.ok;
        if (emitted) jw_raw(&w, ",");
        char id[13];
        hex12(id, d->bssid);
        jw_raw(&w, "{\"id\":");
        jw_str(&w, id);
        jw_raw(&w, ",\"ssid\":");
        jw_str(&w, d->ssid);
        jw_fmt(&w, ",\"ch\":%u,\"rssi\":%d,\"dist\":", (unsigned)d->ch, d->rssi);
        jw_float(&w, dist_m(d->rssi), 1);
        jw_raw(&w, ",\"motion\":");
        jw_float(&w, d->motion, 2);
        jw_raw(&w, ",\"rate\":");
        jw_float(&w, d->rate, 1);
        jw_raw(&w, ",\"flag\":");
        jw_raw(&w, d->flag == 1 ? "\"deauth\"" : d->flag == 2 ? "\"twin\"" : d->flag == 3 ? "\"spoof\"" : "null");
        jw_raw(&w, d->trusted ? ",\"trusted\":true" : ",\"trusted\":false");
        jw_raw(&w, ",\"csi\":[");
        for (int k = 0; k < 64; k++) jw_fmt(&w, k ? ",%u" : "%u", (unsigned)d->csi[k]);
        jw_raw(&w, "],\"pdp\":[");
        for (int k = 0; k < 16; k++) jw_fmt(&w, k ? ",%u" : "%u", (unsigned)d->pdp[k]);
        jw_raw(&w, "]}");
        if (!w.ok) {               /* roll back this entry, keep the frame valid */
            w.len = mark;
            w.b[mark] = 0;
            w.ok = mark_ok;
            break;
        }
        emitted++;
    }
    w.ok = true;
    jw_raw(&w, "],\"ble\":[");
    emitted = 0;
    for (int i = 0; i < nb && w.ok && i < BLE_TABLE; i++) {
        const bled_t *d = &s_bled[i];
        size_t mark = w.len;
        if (emitted) jw_raw(&w, ",");
        char id[13];
        hex12(id, d->addr);
        jw_raw(&w, "{\"id\":");
        jw_str(&w, id);
        jw_raw(&w, ",\"name\":");
        jw_str(&w, d->name);
        jw_fmt(&w, ",\"rssi\":%d,\"dist\":", (int)lrintf(d->rssi));
        jw_float(&w, dist_m((int)lrintf(d->rssi)), 1);
        jw_raw(&w, ",\"kind\":");
        const char *kn = thr_trk_name((trk_kind_t)d->kind);
        if (kn) jw_str(&w, kn);
        else jw_raw(&w, "null");
        jw_fmt(&w, ",\"seen\":%lld", (long long)((now - d->first_us) / 1000000));
        jw_raw(&w, "}");
        if (!w.ok) { w.len = mark; w.b[mark] = 0; w.ok = true; break; }
        emitted++;
    }
    w.ok = true;
    jw_raw(&w, "],\"alerts\":[");
    int nal_out = 0;
    for (int i = 0; i < nal && nal_out < THR_ALERT_OUT && w.ok; i++) {
        const alert_t *al = &s_alerts[i];
        const char *kind = al->kind == THR_DEAUTH ? "deauth" : al->kind == THR_TWIN ? "evil_twin" : "tracker";
        const char *label = al->label;
        if (al->kind == THR_TRACKER && !al->label[0]) label = thr_trk_name(al->trk);
        char id[13], detail[64];
        hex12(id, al->key);
        if (al->kind == THR_DEAUTH) {
            snprintf(detail, sizeof(detail), "%u disconnect frames in %d s", (unsigned)al->n, THR_DEAUTH_WIN_S);
        } else if (al->kind == THR_TWIN) {
            snprintf(detail, sizeof(detail), "open copy of a protected network");
        } else {
            long long mins = (now - al->raised_us + (int64_t)THR_TRACKER_ALERT_S * 1000000) / 60000000LL;
            snprintf(detail, sizeof(detail), "%lld min", mins);
        }
        if (nal_out) jw_raw(&w, ",");
        jw_raw(&w, "{\"kind\":");
        jw_str(&w, kind);
        jw_raw(&w, ",\"id\":");
        jw_str(&w, id);
        jw_raw(&w, ",\"label\":");
        jw_str(&w, label);
        jw_raw(&w, ",\"detail\":");
        jw_str(&w, detail);
        jw_fmt(&w, ",\"age\":%lld}", (long long)((now - al->raised_us) / 1000000));
        nal_out++;
    }
    jw_raw(&w, "],\"link\":{\"mode\":\"");
    jw_raw(&w, link.mode);
    jw_raw(&w, "\",\"state\":\"");
    jw_raw(&w, link.state);
    jw_raw(&w, "\",\"ssid\":");
    if (link.has_ssid) jw_str(&w, link.ssid); else jw_raw(&w, "null");
    jw_raw(&w, "},\"fido\":{\"state\":\"");
    jw_raw(&w, fido_state_str());
    jw_raw(&w, "\"}}");
    if (!w.ok) {
        /* Last resort: an always-valid minimal frame. */
        int n = snprintf(buf, len, "{\"t\":%lld,\"ch\":%u,\"motion\":0,\"presence\":\"present\","
                         "\"away_in\":null,\"why\":null,\"breath\":null,"
                         "\"baseline\":{\"set\":false,\"dev\":0},\"aps\":[],\"ble\":[],\"alerts\":[],"
                         "\"link\":{\"mode\":\"passive\",\"state\":\"off\",\"ssid\":null},"
                         "\"fido\":{\"state\":\"%s\"}}",
                         (long long)(now / 1000), (unsigned)s_channel, fido_state_str());
        return n > 0 ? (size_t)n : 0;
    }
    return w.len;
}

/* ---------- calibrate ---------- */

void sensing_calibrate_start(void)
{
    portENTER_CRITICAL(&s_mux);
    for (int i = 0; i < AP_TABLE; i++) { s_ap[i].cap_n = 0; s_ap[i].cap_sum = 0; }
    s_cal_end_us = now_us() + (int64_t)BASE_CAPTURE_S * 1000000;
    s_cal_active = true;
    portEXIT_CRITICAL(&s_mux);
    ESP_LOGI(TAG, "baseline capture started (%d s)", BASE_CAPTURE_S);
}

void sensing_calibrate_clear(void)
{
    portENTER_CRITICAL(&s_mux);
    s_cal_active = false;
    for (int i = 0; i < AP_TABLE; i++) { s_ap[i].base_set = false; s_ap[i].base_has_shape = false; s_ap[i].base_rssi = 0; }
    portEXIT_CRITICAL(&s_mux);
    memset(s_store, 0, sizeof(s_store));
    store_save(s_store);
    ESP_LOGI(TAG, "baseline cleared");
}

/* ---------- start ---------- */

/* Sensing cannot run: report it in every frame (stub + fault), show LED_ERROR, never lock.
 * The tick never runs, so presence stays at its initial value and no away period starts. */
static void sensing_fault(const char *why)
{
    s_fault = why;
    led_set_fault(true);
    ESP_LOGE(TAG, "sensing offline: %s", why);
}

void sensing_start(void)
{
    if (recovery_safe_mode()) {
        sensing_fault("safe mode after repeated crashes");
        return;
    }
    for (int k = 0; k < 64; k++) {
        for (int t = 0; t < 16; t++) {
            double ang = 2.0 * M_PI * k * t / 64.0;
            s_cos[k][t] = (float)cos(ang);
            s_sin[k][t] = (float)sin(ang);
        }
    }
    for (int i = 0; i < AP_TABLE; i++) {
        s_ap[i].br_v = heap_caps_calloc(BR_N, sizeof(float), MALLOC_CAP_SPIRAM);
        s_ap[i].br_t = heap_caps_calloc(BR_N, sizeof(int64_t), MALLOC_CAP_SPIRAM);
        s_ap[i].br_c = heap_caps_calloc(BR_N, sizeof(uint16_t), MALLOC_CAP_SPIRAM);
        if (!s_ap[i].br_v || !s_ap[i].br_t || !s_ap[i].br_c) {
            ESP_LOGE(TAG, "psram alloc failed for AP slot %d", i);
            sensing_fault("out of memory");
            return;
        }
    }
    store_load();
    s_last_active_us = now_us();
    if (xTaskCreate(sensing_task, "sensing", 6144, NULL, 4, NULL) != pdPASS) {
        sensing_fault("task create failed");
        return;
    }
    if (xTaskCreate(ping_task, "ping", 3072, NULL, 3, NULL) != pdPASS) {
        ESP_LOGE(TAG, "ping task create failed");
    }
}

float sensing_motion(void)
{
    float m;
    portENTER_CRITICAL(&s_mux);
    m = s_motion;
    portEXIT_CRITICAL(&s_mux);
    return m;
}

float sensing_temp_get(void)
{
    float t;
    portENTER_CRITICAL(&s_mux);
    t = s_temp;
    portEXIT_CRITICAL(&s_mux);
    return t;
}
