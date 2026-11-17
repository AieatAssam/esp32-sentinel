#include "sensing_dsp.h"

#include <math.h>
#include <string.h>

#ifdef ESP_PLATFORM
#include "esp_attr.h"
#else
#define EXT_RAM_BSS_ATTR          /* host test build */
#endif

/* Tunables: peak/background power ratio mapped linearly to conf in [0, 1]. */
#define BR_MIN_BPM     6.0f
#define BR_STEP_BPM    0.5f
#define BR_NBINS       49        /* 6..30 bpm in 0.5 bpm steps */
#define BR_RATIO_LO    6.0f      /* conf 0 at or below this ratio */
#define BR_RATIO_HI    16.0f     /* conf 1 at or above this ratio */
#define BR_EXCLUDE     2         /* bins either side of the peak left out of the background */

void dsp_resample(const float *v, const int64_t *t, int n, int64_t t0, int64_t step, float *out, int m)
{
    int j = 0;
    for (int k = 0; k < m; k++) {
        int64_t tk = t0 + (int64_t)k * step;
        while (j + 1 < n && t[j + 1] <= tk) j++;
        if (tk <= t[j] || j + 1 >= n) {
            out[k] = v[j];
        } else {
            float f = (float)(tk - t[j]) / (float)(t[j + 1] - t[j]);
            out[k] = v[j] + f * (v[j + 1] - v[j]);
        }
    }
}

float dsp_shape_rms(const float *mu, const uint8_t *base, uint64_t mask)
{
    double acc = 0.0;
    int cnt = 0;
    for (int k = 0; k < 64; k++) {
        if (!(mask >> k & 1)) continue;
        double e = mu[k] - base[k] / 128.0;
        acc += e * e;
        cnt++;
    }
    return cnt ? (float)sqrt(acc / cnt) : NAN;
}

float dsp_shape_floor(const float *s1, const float *s2, uint32_t n, const float *ref, const uint8_t *base, uint64_t mask)
{
    if (!n) return NAN;
    double acc = 0.0;
    int cnt = 0;
    for (int k = 0; k < 64; k++) {
        if (!(mask >> k & 1)) continue;
        double c = base[k] / 128.0 - ref[k];                /* baseline relative to ref */
        acc += s2[k] / n - 2.0 * c * s1[k] / n + c * c;     /* mean over ticks of (x - base)^2 */
        cnt++;
    }
    return cnt ? (float)sqrt(fmax(0.0, acc / cnt)) : NAN;
}

float dsp_nearness(float dist, float floor, float span)
{
    if (!isfinite(dist) || !isfinite(floor) || !(span > 0.0f)) return NAN;
    float x = (dist - floor) / span;
    return x < 0.0f ? 0.0f : (x > 1.0f ? 1.0f : x);
}

_Static_assert(sizeof(dsp_ble_t) == 16, "BLE cue entry is 16 bytes");

/* Closes the current second into the bin: its mean shape and the noise of that mean. */
static void mot_close_sec(dsp_motion_t *m)
{
    if (m->sn >= DSP_MOT_SEC_MIN) {
        float noise = m->sm2 / (float)(DSP_MASK_N * (m->sn - 1)) / (float)m->sn;
        m->bm++;
        float d2 = 0.0f;
        for (int j = 0; j < DSP_MASK_N; j++) {
            float d = m->smean[j] - m->bmean[j];
            m->bmean[j] += d / m->bm;
            d2 += d * (m->smean[j] - m->bmean[j]);
        }
        m->bm2 += d2;
        m->bnoise += noise;
    }
    m->sn = 0;
    m->sm2 = 0.0f;
}

static void mot_close_bin(dsp_motion_t *m)
{
    m->last_bin = m->bin;
    m->last_ratio = NAN;
    if (m->bm >= DSP_MOT_BIN_MIN && m->bnoise > 0.0f) {
        float between = m->bm2 / (float)(DSP_MASK_N * (m->bm - 1));
        m->last_ratio = between / (m->bnoise / m->bm);
    }
    m->bm = 0;
    m->bm2 = 0.0f;
    m->bnoise = 0.0f;
}

void dsp_motion_advance(dsp_motion_t *m, int64_t t_us)
{
    int32_t sec = (int32_t)(t_us / 1000000), bin = (int32_t)(t_us / DSP_MOT_BIN_US);
    if (!m->started) {
        m->started = true;
        m->sec = sec;
        m->bin = bin;
        m->last_bin = bin - 1;
        m->last_ratio = NAN;
        return;
    }
    if (sec != m->sec) {
        mot_close_sec(m);
        m->sec = sec;
    }
    if (bin != m->bin) {
        mot_close_bin(m);
        m->bin = bin;
    }
}

void dsp_motion_frame(dsp_motion_t *m, const int8_t *iq, const uint8_t *dmac, int sig_mode, int64_t t_us)
{
    if (sig_mode != 1) return;
    /* Majority vote for the dominant destination (Boyer-Moore, capped so a change is followed). */
    bool same = !memcmp(dmac, m->dst, 6);
    if (same) {
        if (m->dst_n < DSP_MOT_DST_CAP) m->dst_n++;
    } else if (m->dst_n == 0) {
        memcpy(m->dst, dmac, 6);
        m->dst_n = 1;
        same = true;
    } else {
        m->dst_n--;
    }
    if (!same) return;
    dsp_motion_advance(m, t_us);

    float a[DSP_MASK_N], sum = 0.0f;
    for (int k = 0, j = 0; k < 64; k++) {
        if (!(DSP_MASK >> k & 1)) continue;
        float im = iq[2 * k], re = iq[2 * k + 1];
        a[j] = sqrtf(re * re + im * im);
        sum += a[j++];
    }
    if (sum <= 0.0f) return;
    float inv = DSP_MASK_N / sum, d2 = 0.0f;
    m->sn++;
    for (int j = 0; j < DSP_MASK_N; j++) {
        float x = a[j] * inv, d = x - m->smean[j];
        m->smean[j] += d / m->sn;
        d2 += d * (x - m->smean[j]);
    }
    m->sm2 += d2;
}

float dsp_motion_ratio(const dsp_motion_t *m, int32_t b)
{
    return m->started && m->last_bin == b ? m->last_ratio : NAN;
}

float dsp_motion_score(float ratio)
{
    return isfinite(ratio) && ratio > 0.0f ? ratio / (ratio + DSP_MOT_K) : 0.0f;
}

bool dsp_sustain_push(dsp_sustain_t *s, bool moving)
{
    s->hist = (uint8_t)(((s->hist << 1) | moving) & 0x3f);
    int n = 0;
    for (int i = 0; i < 6; i++) n += s->hist >> i & 1;
    if (n >= 3) s->left = DSP_SUS_HOLD_BINS - 1;   /* this bin and the next 11 from its start */
    else if (s->left) s->left--;
    return s->left > 0;
}

/* Eviction rank: fewer adverts first (count saturates at 31), then least recently heard. Pure LRU let
 * passing rotating addresses push out a device that advertises every two minutes. */
static int ble_rank(const dsp_ble_t *x, uint16_t now)
{
    return (x->flags >> DSP_BLE_CNT_SHIFT) * 65536 - (uint16_t)(now - x->heard);
}

int dsp_ble_seen(dsp_ble_t *tab, const uint8_t *addr, int rssi, uint32_t now_s, int near_dbm)
{
    uint16_t now = (uint16_t)now_s;
    dsp_ble_t *e = NULL, *victim = NULL;
    for (int i = 0; i < DSP_BLE_N; i++) {
        dsp_ble_t *x = &tab[i];
        if ((x->flags & DSP_BLE_USED) && (uint16_t)(now - x->heard) > DSP_BLE_TTL_S) x->flags = 0;   /* expired */
        if (!(x->flags & DSP_BLE_USED)) { if (!victim || (victim->flags & DSP_BLE_USED)) victim = x; continue; }
        if (!memcmp(x->addr, addr, 6)) { e = x; break; }
        if (!victim || ((victim->flags & DSP_BLE_USED) && ble_rank(x, now) < ble_rank(victim, now))) victim = x;
    }
    if (!e) {                    /* new: a free slot, else the lowest rank */
        e = victim;
        memcpy(e->addr, addr, 6);
        e->flags = DSP_BLE_USED;
        e->first4 = (uint8_t)(now_s / 4);
        e->heard = now;
        e->slow = (float)rssi;
    } else if ((e->flags >> DSP_BLE_CNT_SHIFT) < 31) {
        e->flags += 1 << DSP_BLE_CNT_SHIFT;
    }
    if (!(e->flags & DSP_BLE_MATURE) && (uint8_t)(now_s / 4 - e->first4) >= DSP_BLE_MATURE_S / 4) e->flags |= DSP_BLE_MATURE;
    int r = 0;
    if (rssi >= near_dbm) {
        if (!(e->flags & DSP_BLE_NEAR) && (e->flags & DSP_BLE_MATURE) && e->slow <= DSP_BLE_FAR_DBM) {
            e->flags |= DSP_BLE_NEAR;
            r = 2;
        } else if (e->flags & DSP_BLE_NEAR) {
            r = 1;
        }
        e->strong = now;
    } else if ((e->flags & DSP_BLE_NEAR) && (uint16_t)(now - e->strong) > DSP_BLE_HOLD_S) {
        e->flags &= ~DSP_BLE_NEAR;   /* a weak advert after the hold: it has to qualify again */
    }
    /* The slow average is updated after the check, so it says where the device was before. */
    e->slow += (1.0f - expf(-(float)(uint16_t)(now - e->heard) / DSP_BLE_TAU_S)) * ((float)rssi - e->slow);
    e->heard = now;
    return r;
}

bool dsp_ble_tick(dsp_ble_t *tab, uint32_t now_s, int *heard_s)
{
    uint16_t now = (uint16_t)now_s;
    bool any = false;
    *heard_s = -1;
    for (int i = 0; i < DSP_BLE_N; i++) {
        dsp_ble_t *e = &tab[i];
        if (!(e->flags & DSP_BLE_USED)) continue;
        if ((uint16_t)(now - e->heard) > DSP_BLE_TTL_S) { e->flags = 0; continue; }
        if (!(e->flags & DSP_BLE_MATURE) && (uint8_t)(now_s / 4 - e->first4) >= DSP_BLE_MATURE_S / 4) e->flags |= DSP_BLE_MATURE;
        if (!(e->flags & DSP_BLE_NEAR)) continue;
        int age = (uint16_t)(now - e->strong);
        if (age > DSP_BLE_HOLD_S) continue;   /* NEAR stays set until a weak advert or expiry */
        if (!any || age < *heard_s) *heard_s = age;
        any = true;
    }
    return any;
}

bool dsp_breath_estimate(const float *x, int n, float fs, float *bpm_out, float *conf_out)
{
    *bpm_out = 0.0f;
    *conf_out = 0.0f;
    if (n < 64 || n > SENSING_DSP_MAX_N || fs <= 0.0f) return false;

    double mean = 0.0;
    for (int i = 0; i < n; i++) mean += x[i];
    mean /= n;

    static EXT_RAM_BSS_ATTR float y[SENSING_DSP_MAX_N];   /* PSRAM on the device */
    double energy = 0.0;
    for (int i = 0; i < n; i++) {
        double w = 0.5 * (1.0 - cos(2.0 * M_PI * i / (n - 1)));
        y[i] = (float)((x[i] - mean) * w);
        energy += (double)y[i] * y[i];
    }
    if (energy < 1e-9) return false;

    float pw[BR_NBINS];
    int best = 0;
    for (int b = 0; b < BR_NBINS; b++) {
        double f = (BR_MIN_BPM + b * BR_STEP_BPM) / 60.0;
        double c = 2.0 * cos(2.0 * M_PI * f / fs);
        double s1 = 0.0, s2 = 0.0;
        for (int i = 0; i < n; i++) {
            double s0 = y[i] + c * s1 - s2;
            s2 = s1;
            s1 = s0;
        }
        pw[b] = (float)(s1 * s1 + s2 * s2 - c * s1 * s2);
        if (pw[b] > pw[best]) best = b;
    }

    double bg = 0.0;
    int bg_n = 0;
    for (int b = 0; b < BR_NBINS; b++) {
        if (b >= best - BR_EXCLUDE && b <= best + BR_EXCLUDE) continue;
        bg += pw[b];
        bg_n++;
    }
    bg /= (bg_n ? bg_n : 1);
    double ratio = pw[best] / (bg + 1e-12);
    double conf = (ratio - BR_RATIO_LO) / (BR_RATIO_HI - BR_RATIO_LO);
    if (conf < 0.0) conf = 0.0;
    if (conf > 1.0) conf = 1.0;

    *bpm_out = BR_MIN_BPM + best * BR_STEP_BPM;
    *conf_out = (float)conf;
    return true;
}
