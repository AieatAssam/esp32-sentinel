#pragma once

#include <stdbool.h>
#include <stdint.h>

/* Breathing estimate from a uniformly sampled series x[0..n-1] at fs Hz.
 * A Hann-windowed Goertzel bank scans 6..30 bpm on the mean-removed series. conf is peak power over background power, mapped to 0..1. Returns false when
 * the series is too short or flat (no estimate). n must be <= SENSING_DSP_MAX_N. */
#define SENSING_DSP_MAX_N 1200
bool dsp_breath_estimate(const float *x, int n, float fs, float *bpm_out, float *conf_out);

/* Linear interpolation of irregular samples v at times t[0..n-1] (us, ascending) onto
 * out[0..m-1] at t0 + k*step. Outside the samples the end value is held. Needs n >= 1. */
void dsp_resample(const float *v, const int64_t *t, int n, int64_t t0, int64_t step, float *out, int m);

/* Nearness. Shapes are 64 per-subcarrier normalised amplitudes; mask bit k selects subcarrier k.
 * A baseline shape is stored x128 (uint8). */
/* RMS over the masked subcarriers of mu[k] - base[k] / 128. NAN when the mask is empty. */
float dsp_shape_rms(const float *mu, const uint8_t *base, uint64_t mask);
/* Calibration noise floor: RMS over n ticks and the masked subcarriers of x - base/128, from tick
 * sums s1 = sum(x - ref), s2 = sum((x - ref)^2) taken relative to ref (keeps float sums precise).
 * NAN when n is 0 or the mask is empty. */
float dsp_shape_floor(const float *s1, const float *s2, uint32_t n, const float *ref, const uint8_t *base, uint64_t mask);
/* (dist - floor) / span clamped to 0..1: monotone in dist, 0 at or below the floor.
 * NAN (not available) when dist or floor is not finite or span <= 0. */
float dsp_nearness(float dist, float floor, float span);

/* Motion, per AP, in fixed memory. Frames: HT (sig_mode 1) downlink frames addressed to the AP's
 * dominant destination (online majority vote), each shape renormalised over DSP_MASK. Per whole
 * second with at least DSP_MOT_SEC_MIN frames: the mean shape and the within-second noise of that
 * mean (unbiased per-subcarrier variance / frames). Per 10 s bin with at least DSP_MOT_BIN_MIN such
 * seconds: ratio = variance between the 1 s mean shapes / mean noise of a 1 s mean. About 1 when
 * nothing moves, whatever the frame rate. Seconds and bins are aligned to t / 1 s and t / 10 s. */
#define DSP_MASK          (((1ULL << 27) - 4) | (~0ULL << 38))   /* subcarriers 2..26, 38..63 */
#define DSP_MASK_N        51
#define DSP_MOT_SEC_MIN   5
#define DSP_MOT_BIN_MIN   3
#define DSP_MOT_BIN_US    10000000LL
#define DSP_MOT_DST_CAP   64     /* majority-vote counter cap: a new dominant destination wins within ~2x this */
typedef struct {
    bool started;
    uint8_t dst[6];              /* dominant destination candidate */
    uint16_t dst_n;
    int32_t sec, bin;            /* current second and bin index */
    uint16_t sn;                 /* frames in the current second */
    uint8_t bm;                  /* valid seconds in the current bin */
    float smean[DSP_MASK_N], sm2;    /* Welford over the frames of the second (sm2 summed over subcarriers) */
    float bmean[DSP_MASK_N], bm2;    /* Welford over the 1 s mean shapes of the bin */
    float bnoise;                /* sum over valid seconds of the noise of their mean */
    int32_t last_bin;            /* last closed bin, and its ratio (NAN when it had too few frames) */
    float last_ratio;
} dsp_motion_t;
/* One CSI frame (128 bytes of imag, real pairs) at t_us. Ignored unless sig_mode is 1 (HT) and dmac
 * is the dominant destination. */
void dsp_motion_frame(dsp_motion_t *m, const int8_t *iq, const uint8_t *dmac, int sig_mode, int64_t t_us);
/* Closes the second and bin when t_us has moved past them (also called with no frame). */
void dsp_motion_advance(dsp_motion_t *m, int64_t t_us);
/* Ratio of bin b, NAN when b is not the last closed bin or it had too few frames. */
float dsp_motion_ratio(const dsp_motion_t *m, int32_t b);
/* Ratio mapped to the 0..1 motion score: r / (r + DSP_MOT_K). Monotone, never saturates; noise
 * (r about 1 to 2.5) is 0.03 to 0.07, and the default motion_threshold 0.15 is r = 6. NAN gives 0. */
#define DSP_MOT_K 34.0f
float dsp_motion_score(float ratio);

/* Sustained movement: present when at least 3 of the last 6 bins moved, held for DSP_SUS_HOLD_BINS
 * bins from the start of the last such bin. Feed every closed bin in order. */
#define DSP_SUS_HOLD_BINS 12
typedef struct { uint8_t hist, left; } dsp_sustain_t;   /* zero-initialised: not present */
bool dsp_sustain_push(dsp_sustain_t *s, bool moving);

/* Bluetooth presence cue, a fixed table keyed by address. A device counts once it has been in the
 * table for DSP_BLE_MATURE_S (a full table evicts the entry with the fewest adverts, then the
 * least recently heard), its slow RSSI average (tau DSP_BLE_TAU_S) was at or below
 * DSP_BLE_FAR_DBM, and it is then heard at near_dbm or stronger; it keeps counting while a strong
 * advert came within DSP_BLE_HOLD_S. Times are whole seconds since boot. Address and RSSI only. */
#define DSP_BLE_N         32
#define DSP_BLE_FAR_DBM   (-72)
#define DSP_BLE_HOLD_S    150
#define DSP_BLE_TTL_S     900
#define DSP_BLE_MATURE_S  300
#define DSP_BLE_TAU_S     600.0f
typedef struct {
    uint8_t addr[6];
    uint8_t flags;               /* DSP_BLE_USED | DSP_BLE_MATURE | DSP_BLE_NEAR, adverts - 1 (0..31) in bits 3..7 */
    uint8_t first4;              /* first heard, seconds / 4 (mod 256): only until mature */
    uint16_t heard, strong;      /* last heard, last heard at near_dbm or stronger (seconds mod 65536) */
    float slow;                  /* time-weighted RSSI average */
} dsp_ble_t;
#define DSP_BLE_USED   1
#define DSP_BLE_MATURE 2
#define DSP_BLE_NEAR   4
#define DSP_BLE_CNT_SHIFT 3
/* One advert. Returns 2 when this advert made the device count, 1 when it is a strong advert of a
 * counting device, 0 otherwise. */
int dsp_ble_seen(dsp_ble_t *tab, const uint8_t *addr, int rssi, uint32_t now_s, int near_dbm);
/* Expiry and maturity; call at least every few seconds. Returns true while any device counts, with
 * the seconds since the most recent strong advert of one in *heard_s. */
bool dsp_ble_tick(dsp_ble_t *tab, uint32_t now_s, int *heard_s);
