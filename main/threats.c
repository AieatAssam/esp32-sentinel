#include "threats.h"

#include <string.h>

#define USEC_S 1000000LL

/* Finds a used slot of this kind and key, or takes one. Unknown keys (not a trusted AP) may hold at
 * most THR_UNKNOWN_MAX slots: past that they only recycle an inactive unknown slot. A known key
 * takes a free slot, else the least recent inactive slot, else the least recent unknown slot even
 * when active. NULL when nothing may be taken. */
static thr_slot_t *slot_get(thr_slot_t *tab, int kind, const uint8_t key[6], int64_t now, bool known)
{
    int n_unknown = 0;
    thr_slot_t *free_slot = NULL;
    for (int i = 0; i < THR_SLOTS; i++) {
        if (tab[i].used && tab[i].kind == kind && !memcmp(tab[i].key, key, 6)) {
            if (known) tab[i].known = true;
            return &tab[i];
        }
        if (!tab[i].used && !free_slot) free_slot = &tab[i];
        if (tab[i].used && !tab[i].known) n_unknown++;
    }
    bool unknown_full = !known && n_unknown >= THR_UNKNOWN_MAX;
    thr_slot_t *victim = unknown_full ? NULL : free_slot;
    if (!victim) {   /* least recent inactive slot; unknown keys may only take an unknown one */
        for (int i = 0; i < THR_SLOTS; i++) {
            if (!tab[i].used || tab[i].active) continue;
            if (!known && tab[i].known) continue;
            if (!victim || tab[i].last_us < victim->last_us) victim = &tab[i];
        }
    }
    if (!victim && known) {   /* a trusted AP displaces the least recent unknown entry */
        for (int i = 0; i < THR_SLOTS; i++) {
            if (!tab[i].used || tab[i].known) continue;
            if (!victim || tab[i].last_us < victim->last_us) victim = &tab[i];
        }
    }
    if (!victim) return NULL;
    memset(victim, 0, sizeof(*victim));
    victim->used = true;
    victim->known = known;
    victim->kind = (uint8_t)kind;
    memcpy(victim->key, key, 6);
    victim->last_us = now;
    return victim;
}

thr_slot_t *thr_find(thr_slot_t *tab, int kind, const uint8_t key[6])
{
    for (int i = 0; i < THR_SLOTS; i++) {
        if (tab[i].used && tab[i].kind == kind && !memcmp(tab[i].key, key, 6)) return &tab[i];
    }
    return NULL;
}

uint32_t thr_deauth_count(const thr_slot_t *s, int64_t now)
{
    uint32_t cur = (uint32_t)(now / USEC_S), n = 0;
    for (int i = 0; i < THR_DEAUTH_WIN_S; i++) {
        if (cur - s->sec[i] < THR_DEAUTH_WIN_S) n += s->cnt[i];
    }
    return n;
}

void thr_deauth_frame(thr_slot_t *tab, const uint8_t bssid[6], int64_t now, bool known)
{
    thr_slot_t *s = slot_get(tab, THR_DEAUTH, bssid, now, known);
    if (!s) return;
    uint32_t sec = (uint32_t)(now / USEC_S);
    int i = (int)(sec % THR_DEAUTH_WIN_S);
    if (s->sec[i] != sec) {
        s->sec[i] = sec;
        s->cnt[i] = 0;
    }
    if (s->cnt[i] < 0xFFFF) s->cnt[i]++;
    s->last_us = now;
}

void thr_tick(thr_slot_t *tab, int64_t now)
{
    for (int i = 0; i < THR_SLOTS; i++) {
        thr_slot_t *s = &tab[i];
        if (!s->used || s->kind != THR_DEAUTH) continue;
        if (!s->active && thr_deauth_count(s, now) >= THR_DEAUTH_BURST) {
            s->active = true;
            s->raised_us = now;
        }
        if (s->active && now - s->last_us >= THR_DEAUTH_QUIET_S * USEC_S) s->active = false;
        if (!s->active && now - s->last_us >= THR_DEAUTH_WIN_S * USEC_S) s->used = false;
    }
}

void thr_twin_set(thr_slot_t *tab, const uint8_t key[6], bool flagged, int64_t now, bool known)
{
    if (!flagged) {
        thr_slot_t *s = thr_find(tab, THR_TWIN, key);
        if (s) s->used = false;
        return;
    }
    thr_slot_t *s = slot_get(tab, THR_TWIN, key, now, known);
    if (!s) return;
    if (!s->active) {
        s->active = true;
        s->raised_us = now;
    }
    s->last_us = now;
}

bool thr_same_infra(const uint8_t a[6], const uint8_t b[6])
{
    if (!memcmp(a + 1, b + 1, 5)) return true;   /* multi-SSID pattern: only the first byte differs */
    return (a[0] & ~0x02) == (b[0] & ~0x02) && a[1] == b[1] && a[2] == b[2];
}

int thr_twin_flags(const thr_ap_t *ap, int n, bool *flag)
{
    int count = 0;
    for (int i = 0; i < n; i++) {
        flag[i] = false;
        if (!ap[i].open || !ap[i].ssid[0]) continue;
        for (int j = 0; j < n && !flag[i]; j++) {
            if (j == i || ap[j].open) continue;
            if (!strcmp(ap[i].ssid, ap[j].ssid) && !thr_same_infra(ap[i].bssid, ap[j].bssid)) flag[i] = true;
        }
        count += flag[i];
    }
    return count;
}

bool thr_apple12(const uint8_t *d, size_t n, uint8_t *len, uint8_t *status)
{
    size_t i = 0;
    while (i < n) {
        size_t l = d[i];
        if (l == 0 || i + 1 + l > n) break;
        const uint8_t *v = d + i + 2;
        size_t vl = l - 1;
        if (d[i + 1] == 0xFF && vl >= 4 && v[0] == 0x4C && v[1] == 0x00 && v[2] == 0x12) {
            *len = v[3];
            *status = vl >= 5 ? v[4] : 0;
            return true;
        }
        i += 1 + l;
    }
    return false;
}

const char *thr_trk_name(trk_kind_t k)
{
    switch (k) {
    case TRK_FINDMY: return "findmy";
    case TRK_TILE: return "tile";
    case TRK_AIRTAG: return "airtag";
    case TRK_SMARTTAG: return "smarttag";
    default: return NULL;
    }
}

/* Apple Find My (AirGuard AppleFindMy / DeviceManager): length 0x19 = separated from owner
 * (AirGuard OVERMATURE_OFFLINE). Other lengths are the near-owner form and are not classed.
 * Status bits 4-5: 0 Apple device, 1 AirTag, 2 third-party accessory, 3 AirPods. Only 1 and 2
 * are tracker kinds here. Service data (AirGuard filters): Samsung SmartTag FD5A with first
 * data byte masked 0xF8 == 0x10 (SamsungTracker); Tile FEED with data 02 00 (Tile).
 * ponytail: SmartTag and Tile are not gated on separated state (AirGuard shows no gate). */
trk_kind_t thr_ble_kind(const uint8_t *d, size_t n)
{
    uint8_t len = 0, st = 0;
    if (thr_apple12(d, n, &len, &st)) {
        if (len != 0x19) return TRK_NONE;
        switch ((st & 0x30) >> 4) {
        case 1: return TRK_AIRTAG;
        case 2: return TRK_FINDMY;
        default: return TRK_NONE;
        }
    }
    size_t i = 0;
    while (i < n) {
        size_t l = d[i];
        if (l == 0 || i + 1 + l > n) break;
        const uint8_t *v = d + i + 2;
        size_t vl = l - 1;
        if (d[i + 1] == 0x16 && vl >= 3) {
            if (v[0] == 0x5A && v[1] == 0xFD && (v[2] & 0xF8) == 0x10) return TRK_SMARTTAG;
            if (v[0] == 0xED && v[1] == 0xFE && vl >= 4 && v[2] == 0x02 && v[3] == 0x00) return TRK_TILE;
        }
        i += 1 + l;
    }
    return TRK_NONE;
}

bool thr_tracker_alert(int64_t first, int64_t last, int64_t now)
{
    return now - last <= THR_TRACKER_GAP_S * USEC_S && now - first >= THR_TRACKER_ALERT_S * USEC_S;
}

bool thr_ap_learned(int64_t learn_start_us, int64_t now_us)
{
    return now_us - learn_start_us >= THR_LEARN_S * USEC_S;
}

bool thr_ap_counts(bool trusted, bool spoofed, bool any_trusted, int64_t since_epoch_us)
{
    if (spoofed) return false;
    if (trusted) return true;
    return !any_trusted && since_epoch_us < THR_BOOTSTRAP_S * USEC_S;
}

bool thr_beacon(thr_bcn_t *b, uint16_t seq, uint64_t tsf, int64_t now)
{
    seq &= 0x0FFF;
    if (b->have) {
        bool anomaly = false;
        uint16_t dseq = (uint16_t)((seq - b->seq) & 0x0FFF);
        if (dseq == 0 || dseq > 2048) anomaly = true;        /* repeated or backwards */
        if (tsf < b->tsf) {
            anomaly = true;                                  /* TSF went backwards */
        } else {
            int64_t dt_tsf = (int64_t)(tsf - b->tsf);
            int64_t dt_loc = now - b->local_us;
            int64_t diff = dt_tsf - dt_loc;
            if (diff > THR_BCN_TSF_TOL_US || diff < -THR_BCN_TSF_TOL_US) anomaly = true;
        }
        if (now - b->win_us > THR_BCN_WIN_S * USEC_S) {
            b->win_us = now;
            b->anomalies = 0;
        }
        if (anomaly && b->anomalies < 255) b->anomalies++;
        if (b->anomalies >= THR_BCN_ANOMALIES) b->spoof_until_us = now + THR_BCN_HOLD_S * USEC_S;
    } else {
        b->have = true;
        b->win_us = now;
    }
    b->seq = seq;
    b->tsf = tsf;
    b->local_us = now;
    return now < b->spoof_until_us;
}

int thr_ap_slot(const thr_ap_ev_t *ev, int n, int64_t now)
{
    int victim = -1;
    for (int i = 0; i < n; i++) {
        if (!ev[i].used) return i;
    }
    for (int i = 0; i < n; i++) {
        if (ev[i].trusted) continue;
        bool weak = now - ev[i].last_us > THR_AP_STALE_S * USEC_S || ev[i].beacons < THR_AP_MIN_BEACONS;
        if (!weak) continue;
        if (victim < 0 || ev[i].last_us < ev[victim].last_us) victim = i;
    }
    return victim;
}

void thr_trk_seen(thr_trk_t *tab, const uint8_t addr[6], uint8_t kind, int64_t now)
{
    thr_trk_t *e = NULL;
    for (int i = 0; i < THR_TRK_SLOTS; i++) {
        if (tab[i].used && !memcmp(tab[i].addr, addr, 6)) { e = &tab[i]; break; }
    }
    if (e) {
        if (now - e->last_us > THR_TRACKER_GAP_S * USEC_S) e->first_us = now;
    } else {
        for (int i = 0; i < THR_TRK_SLOTS && !e; i++) if (!tab[i].used) e = &tab[i];
        for (int i = 0; i < THR_TRK_SLOTS; i++) {   /* stale: oldest last_us */
            if (e && !e->used) break;
            if (now - tab[i].last_us <= THR_TRACKER_GAP_S * USEC_S) continue;
            if (!e || tab[i].last_us < e->last_us) e = &tab[i];
        }
        if (!e) {                                   /* least evidence: latest first_us */
            for (int i = 0; i < THR_TRK_SLOTS; i++) if (!e || tab[i].first_us > e->first_us) e = &tab[i];
        }
        memset(e, 0, sizeof(*e));
        e->used = true;
        memcpy(e->addr, addr, 6);
        e->first_us = now;
    }
    e->last_us = now;
    e->kind = kind;
}

void thr_trk_tick(thr_trk_t *tab, int64_t now)
{
    for (int i = 0; i < THR_TRK_SLOTS; i++) {
        if (tab[i].used && now - tab[i].last_us > THR_TRACKER_GAP_S * USEC_S) tab[i].used = false;
    }
}

size_t thr_json_escape(char *out, size_t cap, const char *s)
{
    static const char hx[] = "0123456789abcdef";
    if (cap < 3) return 0;
    size_t n = 0;
    out[n++] = '"';
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        char e[6];
        size_t el = 1;
        if (*p == '"' || *p == '\\') {
            e[0] = '\\';
            e[1] = (char)*p;
            el = 2;
        } else if (*p < 0x20) {
            e[0] = '\\'; e[1] = 'u'; e[2] = '0'; e[3] = '0';
            e[4] = hx[*p >> 4]; e[5] = hx[*p & 15];
            el = 6;
        } else if (*p >= 0x80) {
            e[0] = '?';               /* non-ASCII bytes are attacker bytes: drop them to '?' */
        } else {
            e[0] = (char)*p;
        }
        if (n + el + 2 > cap) return 0;   /* +2: closing quote and NUL */
        memcpy(out + n, e, el);
        n += el;
    }
    if (n + 2 > cap) return 0;
    out[n++] = '"';
    out[n] = 0;
    return n;
}
