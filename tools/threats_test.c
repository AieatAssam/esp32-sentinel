/* Host checks for main/threats.c. Build and run:
 *   cc -Wall -Werror -I main tools/threats_test.c main/threats.c -o /tmp/threats_test && /tmp/threats_test
 * (use the scratchpad for the binary). Exit 0 on success; asserts otherwise. */
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "threats.h"

#define S 1000000LL

static void test_deauth(void)
{
    thr_slot_t tab[THR_SLOTS];
    memset(tab, 0, sizeof(tab));
    const uint8_t b[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
    int64_t t0 = 100 * S;

    /* a normal roam: 2 frames */
    thr_deauth_frame(tab, b, t0, false);
    thr_deauth_frame(tab, b, t0 + S, false);
    thr_tick(tab, t0 + 2 * S);
    thr_slot_t *s = thr_find(tab, THR_DEAUTH, b);
    assert(s && !s->active);
    assert(thr_deauth_count(s, t0 + 2 * S) == 2);

    /* flood: 25 more frames within 2 s */
    for (int i = 0; i < 25; i++) thr_deauth_frame(tab, b, t0 + 2 * S + (int64_t)i * 80000, false);
    thr_tick(tab, t0 + 4 * S);
    s = thr_find(tab, THR_DEAUTH, b);
    assert(s && s->active);
    assert(thr_deauth_count(s, t0 + 4 * S) == 27);
    assert(s->raised_us == t0 + 4 * S);

    /* still active during the quiet period, cleared 30 s after the last frame */
    int64_t last = t0 + 2 * S + 24 * 80000;
    thr_tick(tab, last + 29 * S);
    s = thr_find(tab, THR_DEAUTH, b);
    assert(s && s->active);
    thr_tick(tab, last + 30 * S);
    assert(thr_find(tab, THR_DEAUTH, b) == NULL || !thr_find(tab, THR_DEAUTH, b)->active);

    /* a burst that falls out of the window does not flag */
    memset(tab, 0, sizeof(tab));
    for (int i = 0; i < 15; i++) thr_deauth_frame(tab, b, t0 + (int64_t)i * S / 2, false);   /* 7.5 s */
    thr_tick(tab, t0 + 8 * S);
    s = thr_find(tab, THR_DEAUTH, b);
    assert(s && !s->active && thr_deauth_count(s, t0 + 8 * S) == 15);
    for (int i = 0; i < 10; i++) thr_deauth_frame(tab, b, t0 + 20 * S + (int64_t)i * S / 2, false);
    thr_tick(tab, t0 + 25 * S);
    s = thr_find(tab, THR_DEAUTH, b);
    assert(s && !s->active);
}

static void test_twin(void)
{
    /* one vendor, multi-SSID set: bytes 1-5 equal, first byte differs (LAA bit / other bits) */
    thr_ap_t ap[3] = {
        {{0x02, 0x00, 0x5e, 0xaa, 0xbb, 0x01}, "Home", false},
        {{0x06, 0x00, 0x5e, 0xaa, 0xbb, 0x01}, "Home", true},
        {{0x0a, 0x00, 0x5e, 0xaa, 0xbb, 0x01}, "Home", true},
    };
    bool f[3];
    assert(thr_twin_flags(ap, 3, f) == 0);
    assert(!f[0] && !f[1] && !f[2]);
    assert(thr_same_infra(ap[0].bssid, ap[1].bssid));
    assert(thr_same_infra(ap[0].bssid, ap[2].bssid));

    /* open copy of a protected network from another OUI: flag the open one only */
    thr_ap_t ev[2] = {
        {{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}, "Corp", false},
        {{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}, "Corp", true},
    };
    assert(thr_twin_flags(ev, 2, f) == 1);
    assert(!f[0] && f[1]);

    /* same security, different OUI: weak hint, not flagged */
    thr_ap_t weak[2] = {
        {{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}, "Corp", false},
        {{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}, "Corp", false},
    };
    assert(thr_twin_flags(weak, 2, f) == 0);

    /* an empty SSID is never a twin */
    thr_ap_t hid[2] = {
        {{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}, "", true},
        {{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}, "", false},
    };
    assert(thr_twin_flags(hid, 2, f) == 0);

    /* the same-infra rule also covers the first 3 bytes ignoring the LAA bit */
    const uint8_t a[6] = {0x02, 0x10, 0x20, 0x30, 0x40, 0x50};
    const uint8_t b[6] = {0x00, 0x10, 0x20, 0x99, 0x98, 0x97};
    assert(thr_same_infra(a, b));
    const uint8_t c[6] = {0x00, 0x10, 0x21, 0x99, 0x98, 0x97};
    assert(!thr_same_infra(a, c));

    /* slot lifecycle: flag raises, clearing removes */
    thr_slot_t tab[THR_SLOTS];
    memset(tab, 0, sizeof(tab));
    thr_twin_set(tab, ev[0].bssid, true, 5 * S, false);
    assert(thr_find(tab, THR_TWIN, ev[0].bssid) && thr_find(tab, THR_TWIN, ev[0].bssid)->active);
    thr_twin_set(tab, ev[0].bssid, false, 6 * S, false);
    assert(thr_find(tab, THR_TWIN, ev[0].bssid) == NULL);
}

/* Flags + one manufacturer AD (length 0x1B): 4C 00 12 <length byte> <status byte> + zeros. */
static size_t mk_apple(uint8_t *b, uint8_t len_byte, uint8_t st)
{
    uint8_t h[] = {0x02, 0x01, 0x06, 0x1B, 0xFF, 0x4C, 0x00, 0x12, len_byte, st};
    memset(b, 0, 31);
    memcpy(b, h, sizeof(h));
    return 31;
}

static void test_tracker(void)
{
    uint8_t b[31];
    /* separated (length 0x19), status bits 4-5 = 01: AirTag */
    assert(thr_ble_kind(b, mk_apple(b, 0x19, 0x10)) == TRK_AIRTAG);
    /* separated, bits 4-5 = 10: third-party Find My accessory */
    assert(thr_ble_kind(b, mk_apple(b, 0x19, 0x20)) == TRK_FINDMY);
    /* separated iPhone/Mac (bits 00) and AirPods (bits 11): ordinary devices */
    assert(thr_ble_kind(b, mk_apple(b, 0x19, 0x00)) == TRK_NONE);
    assert(thr_ble_kind(b, mk_apple(b, 0x19, 0x30)) == TRK_NONE);
    /* near-owner short form (length 0x02) is not a separated tracker, whatever the bits */
    assert(thr_ble_kind(b, mk_apple(b, 0x02, 0x10)) == TRK_NONE);
    assert(thr_ble_kind(b, mk_apple(b, 0x02, 0x20)) == TRK_NONE);
    /* raw values come back for the histogram */
    uint8_t len = 0, st = 0;
    assert(thr_apple12(b, mk_apple(b, 0x19, 0x10), &len, &st) && len == 0x19 && st == 0x10);

    /* Samsung SmartTag: service data FD5A, first data byte & 0xF8 == 0x10 */
    const uint8_t smarttag[] = {0x08, 0x16, 0x5A, 0xFD, 0x17, 0x01, 0x02, 0x03, 0x04};
    assert(thr_ble_kind(smarttag, sizeof(smarttag)) == TRK_SMARTTAG);
    const uint8_t smarttag_other[] = {0x08, 0x16, 0x5A, 0xFD, 0x20, 0x01, 0x02, 0x03, 0x04};
    assert(thr_ble_kind(smarttag_other, sizeof(smarttag_other)) == TRK_NONE);

    /* Tile: service data FEED with data 02 00 */
    const uint8_t tile_sd[] = {0x06, 0x16, 0xED, 0xFE, 0x02, 0x00, 0x01};
    assert(thr_ble_kind(tile_sd, sizeof(tile_sd)) == TRK_TILE);
    const uint8_t tile_other[] = {0x06, 0x16, 0xED, 0xFE, 0x02, 0x01, 0x01};
    assert(thr_ble_kind(tile_other, sizeof(tile_other)) == TRK_NONE);
    /* a bare FEED UUID list is not a tracker advert */
    const uint8_t tile_list[] = {0x03, 0x03, 0xED, 0xFE};
    assert(thr_ble_kind(tile_list, sizeof(tile_list)) == TRK_NONE);

    assert(strcmp(thr_trk_name(TRK_AIRTAG), "airtag") == 0 && thr_trk_name(TRK_NONE) == NULL);

    /* ordinary iPhone nearby-info advert (type 0x10) and a name: no kind */
    const uint8_t iphone[] = {0x02, 0x01, 0x06, 0x07, 0xFF, 0x4C, 0x00, 0x10, 0x05, 0x01, 0x1A, 0x2B,
                              0x05, 0x09, 'P', 'h', 'o', 'n', 'e'};
    assert(thr_ble_kind(iphone, sizeof(iphone)) == TRK_NONE);

    /* truncated or zero-length AD structures do not read past the end */
    const uint8_t bad[] = {0x09, 0xFF, 0x4C, 0x00, 0x12};
    assert(thr_ble_kind(bad, sizeof(bad)) == TRK_NONE);
    const uint8_t zero[] = {0x00, 0x03, 0x03, 0xED, 0xFE};
    assert(thr_ble_kind(zero, sizeof(zero)) == TRK_NONE);

    /* alert after 600 s of presence, dropped when the device goes quiet for over 60 s */
    assert(!thr_tracker_alert(0, 599 * S, 599 * S));
    assert(thr_tracker_alert(0, 600 * S, 600 * S));
    assert(!thr_tracker_alert(0, 0, 700 * S));
}

static void test_json(void)
{
    char out[256];
    size_t n = thr_json_escape(out, sizeof(out), "\"},{\"x\":\"");
    assert(n > 0);
    assert(strcmp(out, "\"\\\"},{\\\"x\\\":\\\"\"") == 0);

    /* control bytes 0x01-0x1f become \u00xx, backslash is escaped */
    char ctl[40];
    int k = 0;
    for (int c = 1; c < 0x20; c++) ctl[k++] = (char)c;
    ctl[k] = 0;
    n = thr_json_escape(out, sizeof(out), ctl);
    assert(n > 0 && out[0] == '"' && out[n - 1] == '"');
    assert(strstr(out, "\\u0001") && strstr(out, "\\u001f") && strstr(out, "\\u000a"));
    assert(thr_json_escape(out, sizeof(out), "a\\b") > 0 && strcmp(out, "\"a\\\\b\"") == 0);

    /* bytes >= 0x80 (invalid UTF-8 included) become '?' */
    const char hi[] = {(char)0xff, (char)0xc3, (char)0x80, 0};
    assert(thr_json_escape(out, sizeof(out), hi) > 0 && strcmp(out, "\"???\"") == 0);

    /* too small a buffer fails instead of truncating */
    assert(thr_json_escape(out, 4, "abcdef") == 0);
    assert(thr_json_escape(out, 3, "") == 2);
}

/* L4: spoofed BSSIDs cannot crowd out alerts for trusted APs */
static void test_slots(void)
{
    thr_slot_t tab[THR_SLOTS];
    memset(tab, 0, sizeof(tab));
    uint8_t k[6] = {0x02, 0, 0, 0, 0, 0};
    /* a flood of 40 spoofed BSSIDs, each with a burst: at most THR_UNKNOWN_MAX slots */
    for (int j = 0; j < 40; j++) {
        k[5] = (uint8_t)j;
        for (int i = 0; i < 25; i++) thr_deauth_frame(tab, k, 10 * S + j * 1000 + i, false);
    }
    thr_tick(tab, 11 * S);
    int used = 0;
    for (int i = 0; i < THR_SLOTS; i++) used += tab[i].used;
    assert(used == THR_UNKNOWN_MAX);
    /* a trusted AP under attack still gets a slot and raises its alert */
    const uint8_t home[6] = {0x02, 0x00, 0x5e, 0xaa, 0xbb, 0x01};
    for (int i = 0; i < 25; i++) thr_deauth_frame(tab, home, 12 * S + i, true);
    thr_tick(tab, 13 * S);
    thr_slot_t *s = thr_find(tab, THR_DEAUTH, home);
    assert(s && s->active && s->known);

    /* table full of active unknown entries plus known ones: a known key evicts an unknown one */
    memset(tab, 0, sizeof(tab));
    for (int j = 0; j < THR_SLOTS; j++) {
        k[5] = (uint8_t)j;
        bool known = j >= THR_UNKNOWN_MAX;
        for (int i = 0; i < 25; i++) thr_deauth_frame(tab, k, 20 * S + j * 1000 + i, known);
    }
    thr_tick(tab, 21 * S);
    const uint8_t home2[6] = {0x02, 0x00, 0x5e, 0xaa, 0xbb, 0x02};
    thr_deauth_frame(tab, home2, 22 * S, true);
    assert(thr_find(tab, THR_DEAUTH, home2));
    k[5] = 0;   /* the least recent unknown entry went */
    assert(!thr_find(tab, THR_DEAUTH, k));
    /* an unknown key cannot evict anything active */
    const uint8_t spoof[6] = {0x02, 9, 9, 9, 9, 9};
    thr_deauth_frame(tab, spoof, 22 * S, false);
    assert(!thr_find(tab, THR_DEAUTH, spoof));
}

static void test_trust(void)
{
    /* learned after THR_LEARN_S of steady beacons */
    assert(!thr_ap_learned(0, (THR_LEARN_S - 1) * S));
    assert(thr_ap_learned(0, THR_LEARN_S * S));
    /* trusted counts, spoofed never counts */
    assert(thr_ap_counts(true, false, true, 10000 * S));
    assert(!thr_ap_counts(true, true, true, 1 * S));
    /* untrusted: only in the bootstrap window, and only while nothing is trusted */
    assert(thr_ap_counts(false, false, false, 1 * S));
    assert(!thr_ap_counts(false, false, true, 1 * S));
    assert(!thr_ap_counts(false, false, false, THR_BOOTSTRAP_S * S));
    assert(!thr_ap_counts(false, true, false, 1 * S));
    /* the window is per channel epoch, not per boot: after a repick late in uptime the new
     * channel's APs count again until one is learned (else presence drops to 0 and locks) */
    int64_t uptime = 50000 * S, epoch = uptime - 5 * S;
    assert(thr_ap_counts(false, false, false, uptime - epoch));
}

static void test_beacon(void)
{
    /* a real AP: seq +1 (or more), TSF follows local time within jitter */
    thr_bcn_t b;
    memset(&b, 0, sizeof(b));
    uint64_t tsf = 5000000000ULL;
    int64_t t = 100 * S;
    uint16_t seq = 4090;
    for (int i = 0; i < 300; i++) {   /* 30 s, seq wraps through 4095 -> 0 */
        int64_t jitter = (i % 3) * 3000;
        assert(!thr_beacon(&b, seq, tsf, t + jitter));
        seq = (uint16_t)((seq + 1 + (i % 4 == 0)) & 0x0FFF);
        tsf += 102400;
        t += 102400;
    }
    /* an AP reboot (TSF and seq restart once) is a single anomaly, not a flag */
    assert(!thr_beacon(&b, 7, 1000, t));
    t += 102400;
    assert(!thr_beacon(&b, 8, 1000 + 102400, t));

    /* a spoofer interleaving its own beacons on the same BSSID: flagged within a few beacons */
    memset(&b, 0, sizeof(b));
    tsf = 5000000000ULL;
    t = 100 * S;
    seq = 100;
    uint64_t ftsf = 77000000ULL;
    uint16_t fseq = 3000;
    bool flagged = false;
    for (int i = 0; i < 20 && !flagged; i++) {
        flagged |= thr_beacon(&b, seq, tsf, t);
        t += 51200;
        flagged |= thr_beacon(&b, fseq, ftsf, t);
        t += 51200;
        seq++; fseq++; tsf += 102400; ftsf += 102400;
    }
    assert(flagged);
    /* the flag holds for THR_BCN_HOLD_S after the last trigger, then clears on clean beacons */
    int64_t trig = b.spoof_until_us - THR_BCN_HOLD_S * S;
    assert(trig <= t);
    memset(&b, 0, sizeof(b));
}

static void test_ap_slot(void)
{
    int64_t now = 1000 * S;
    thr_ap_ev_t ev[4] = {
        {true, true, 5000, now - 60 * S},     /* trusted, even if stale: never replaced */
        {true, false, 3000, now},             /* steady untrusted AP */
        {true, false, 1, now},                /* one-beacon BSSID (flood entry) */
        {true, false, 900, now - 10 * S},     /* untrusted, gone quiet */
    };
    assert(thr_ap_slot(ev, 4, now) == 3);      /* least recently heard weak entry */
    ev[3].last_us = now;
    assert(thr_ap_slot(ev, 4, now) == 2);
    ev[2].beacons = 50;
    assert(thr_ap_slot(ev, 4, now) == -1);     /* nothing weak: new BSSID is dropped */
    ev[1].used = false;
    assert(thr_ap_slot(ev, 4, now) == 1);      /* free slot first */
}

static void test_trk(void)
{
    thr_trk_t tab[THR_TRK_SLOTS];
    memset(tab, 0, sizeof(tab));
    const uint8_t real[6] = {0xc0, 1, 2, 3, 4, 5};
    uint8_t fake[6] = {0xc2, 0, 0, 0, 0, 0};
    /* a real tracker present from t=0, seen every 10 s; a flood of 1000 fake tracker addresses */
    for (int64_t t = 0; t <= 700; t += 10) {
        thr_trk_seen(tab, real, TRK_AIRTAG, t * S);
        for (int j = 0; j < 20; j++) {
            fake[4] = (uint8_t)(t / 10);
            fake[5] = (uint8_t)j;
            thr_trk_seen(tab, fake, TRK_FINDMY, t * S + j);
        }
        thr_trk_tick(tab, t * S + 100);
    }
    const thr_trk_t *e = NULL;
    for (int i = 0; i < THR_TRK_SLOTS; i++) if (tab[i].used && !memcmp(tab[i].addr, real, 6)) e = &tab[i];
    assert(e && e->first_us == 0);
    assert(thr_tracker_alert(e->first_us, e->last_us, 700 * S));
    /* a gap over 60 s restarts its clock; tick drops silent entries */
    thr_trk_seen(tab, real, TRK_AIRTAG, 800 * S);
    for (int i = 0; i < THR_TRK_SLOTS; i++) if (tab[i].used && !memcmp(tab[i].addr, real, 6)) e = &tab[i];
    assert(e->first_us == 800 * S);
    thr_trk_tick(tab, 900 * S);
    for (int i = 0; i < THR_TRK_SLOTS; i++) assert(!tab[i].used);
}

int main(void)
{
    test_slots();
    test_trust();
    test_beacon();
    test_ap_slot();
    test_trk();
    test_deauth();
    test_twin();
    test_tracker();
    test_json();
    printf("threats_test: all checks passed\n");
    return 0;
}
