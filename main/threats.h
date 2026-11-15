#pragma once

/* Passive threat heuristics for the sensing frame: deauth/disassoc bursts, evil-twin hints,
 * BLE tracker adverts, and the JSON string escaper. Pure: no ESP-IDF headers, so
 * tools/threats_test.c builds it on the host. Callers hold the sensing lock (s_mux). */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* ---------- tunables ---------- */
#define THR_DEAUTH_BURST     20     /* deauth+disassoc frames per BSSID in the window that flag it */
#define THR_DEAUTH_WIN_S     10     /* sliding window; also the bucket count (1 s buckets) */
#define THR_DEAUTH_QUIET_S   30     /* a deauth flag clears after this long with no such frame */
#define THR_TRACKER_ALERT_S  600    /* a tracker-kind device followed this long raises an alert */
#define THR_TRACKER_GAP_S    60     /* a gap longer than this restarts the following clock */
#define THR_SLOTS            16     /* deauth + evil-twin alert slots */
#define THR_ALERT_OUT        8      /* alerts emitted in the frame */
#define THR_UNKNOWN_MAX      10     /* alert slots that BSSIDs outside the trusted AP set may hold; the
                                       rest stay free for trusted APs, which may also evict them */
/* Presence sources (see thr_ap_counts). */
#define THR_LEARN_S          600    /* an AP beaconing steadily this long since admission is learned */
#define THR_LEARN_GAP_S      5      /* a beacon gap longer than this restarts learning */
#define THR_BOOTSTRAP_S      600    /* after boot or a channel change, untrusted APs count only while no AP is trusted */
/* Beacon spoof detector (see thr_beacon). */
#define THR_BCN_TSF_TOL_US   50000  /* beacon TSF advance may differ from local time by this much */
#define THR_BCN_WIN_S        10     /* anomaly counting window */
#define THR_BCN_ANOMALIES    3      /* anomalies in one window that flag the BSSID as spoofed */
#define THR_BCN_HOLD_S       60     /* how long a spoofed flag lasts after the last trigger */
/* AP table admission (see thr_ap_slot). */
#define THR_AP_STALE_S       5      /* an untrusted AP not heard for this long may be replaced */
#define THR_AP_MIN_BEACONS   5      /* an untrusted AP with fewer beacons than this may be replaced */
/* Tracker table (see thr_trk_seen). */
#define THR_TRK_SLOTS        16

typedef enum { THR_NONE = 0, THR_DEAUTH, THR_TWIN, THR_TRACKER } thr_kind_t;
typedef enum { TRK_NONE = 0, TRK_FINDMY, TRK_TILE, TRK_AIRTAG, TRK_SMARTTAG } trk_kind_t;

typedef struct {
    bool used;
    bool active;                  /* alert raised */
    bool known;                   /* key is a trusted AP (slot reserved, see THR_UNKNOWN_MAX) */
    uint8_t kind;                 /* thr_kind_t */
    uint8_t key[6];               /* BSSID */
    int64_t last_us;              /* last matching frame (deauth) or last evaluation (twin) */
    int64_t raised_us;            /* when the alert went active */
    uint32_t sec[THR_DEAUTH_WIN_S];  /* deauth: absolute second each bucket holds */
    uint16_t cnt[THR_DEAUTH_WIN_S];  /* deauth: frames in that second */
} thr_slot_t;

typedef struct {
    uint8_t bssid[6];
    char ssid[33];
    bool open;                    /* no privacy bit and no RSN/WPA IE */
} thr_ap_t;

/* Deauth/disassoc frame from the air; bssid is addr3. known: the BSSID is a trusted AP. Frames for
 * unknown BSSIDs may hold at most THR_UNKNOWN_MAX slots, so spoofed BSSIDs cannot crowd out the
 * alerts for trusted APs; a trusted AP may evict the least recent unknown entry. */
void thr_deauth_frame(thr_slot_t *tab, const uint8_t bssid[6], int64_t now_us, bool known);
/* Frames in the sliding window for one deauth slot. */
uint32_t thr_deauth_count(const thr_slot_t *s, int64_t now_us);
/* Raises and clears deauth alerts. Call about every 100 ms. */
void thr_tick(thr_slot_t *tab, int64_t now_us);
/* Looks up a slot of the given kind (thr_kind_t) by key; NULL when absent. */
thr_slot_t *thr_find(thr_slot_t *tab, int kind, const uint8_t key[6]);
/* Sets or clears the evil-twin alert for one BSSID. known: as for thr_deauth_frame (the copied
 * network is a trusted AP). */
void thr_twin_set(thr_slot_t *tab, const uint8_t key[6], bool flagged, int64_t now_us, bool known);

/* Same infrastructure: bytes 1-5 equal, or bytes 0-2 equal ignoring the locally-administered bit. */
bool thr_same_infra(const uint8_t a[6], const uint8_t b[6]);
/* Flags open APs that share a non-empty SSID with a protected AP from other infrastructure.
 * Same-security copies are not flagged (too many false alarms). Returns the number flagged. */
int thr_twin_flags(const thr_ap_t *ap, int n, bool *flag);

/* Finds the Apple Find My advert (company 0x004C, type 0x12) and reports its length byte and
 * status byte (0 when absent). Returns false when there is none. */
bool thr_apple12(const uint8_t *d, size_t n, uint8_t *len, uint8_t *status);
/* Classifies one BLE advert (raw AD structures). TRK_NONE when not a confirmed tracker state. */
trk_kind_t thr_ble_kind(const uint8_t *d, size_t n);
/* Kind name for the JSON output and alert labels; NULL for TRK_NONE. */
const char *thr_trk_name(trk_kind_t k);
/* True when a tracker device has been present continuously for THR_TRACKER_ALERT_S. */
bool thr_tracker_alert(int64_t first_us, int64_t last_us, int64_t now_us);

/* ---------- presence-source trust ----------
 * A passive receiver cannot authenticate 802.11 frames. These rules decide which APs may feed
 * presence: a trusted AP (empty-room baseline, the joined AP, or learned by beaconing steadily for
 * THR_LEARN_S) counts; a BSSID that just appeared does not. Right after boot, before anything is
 * learned, untrusted APs count so presence works at once (bootstrap). A BSSID whose beacons look
 * like two transmitters (see thr_beacon) never counts while flagged. */
bool thr_ap_learned(int64_t learn_start_us, int64_t now_us);
bool thr_ap_counts(bool trusted, bool spoofed, bool any_trusted, int64_t since_epoch_us);

/* Beacon spoof detector for one BSSID. A second transmitter using the same BSSID shows up as
 * sequence numbers that go backwards or a TSF that does not advance with local time. */
typedef struct {
    bool have;
    uint16_t seq;              /* 12-bit sequence number of the last beacon */
    uint64_t tsf;              /* timestamp field of the last beacon */
    int64_t local_us;          /* local receive time of the last beacon */
    int64_t win_us;            /* start of the anomaly window */
    uint8_t anomalies;         /* in the current window */
    int64_t spoof_until_us;    /* flagged until this time */
} thr_bcn_t;
/* Feeds one beacon. Returns true while the BSSID is flagged as spoofed. */
bool thr_beacon(thr_bcn_t *b, uint16_t seq, uint64_t tsf, int64_t now_us);

/* AP table admission. Returns the index a new BSSID may take: a free slot, else the weakest
 * untrusted entry (not heard for THR_AP_STALE_S or fewer than THR_AP_MIN_BEACONS beacons, least
 * recently heard first). Trusted entries are never replaced. -1 when nothing may be replaced. */
typedef struct {
    bool used;
    bool trusted;
    uint32_t beacons;
    int64_t last_us;
} thr_ap_ev_t;
int thr_ap_slot(const thr_ap_ev_t *ev, int n, int64_t now_us);

/* Tracker table, keyed by BLE address and separate from the display table, so the "followed
 * since" clock of a real tracker survives a flood of other adverts. A new address takes a free
 * slot, else a stale one (silent for over THR_TRACKER_GAP_S), else replaces the entry seen for
 * the shortest time (least evidence). */
typedef struct {
    bool used;
    uint8_t addr[6];
    uint8_t kind;              /* trk_kind_t */
    int64_t first_us;          /* start of continuous presence */
    int64_t last_us;
} thr_trk_t;
void thr_trk_seen(thr_trk_t *tab, const uint8_t addr[6], uint8_t kind, int64_t now_us);
/* Drops entries silent for over THR_TRACKER_GAP_S. */
void thr_trk_tick(thr_trk_t *tab, int64_t now_us);

/* Writes a quoted, JSON-escaped string. Returns the length (excluding NUL), or 0 when cap is too small. */
size_t thr_json_escape(char *out, size_t cap, const char *s);
