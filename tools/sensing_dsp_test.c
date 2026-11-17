/* Host checks for main/sensing_dsp.c. Build and run (binary in the scratchpad):
 *   cc -Wall -Werror -I main tools/sensing_dsp_test.c main/sensing_dsp.c -lm -o <scratchpad>/sensing_dsp_test
 * Exit 0 when every case holds; asserts otherwise. */
#include <assert.h>
#include <math.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "sensing_dsp.h"

#define N 300          /* 30 s at 10 Hz */
#define FS 10.0f

static uint32_t lcg = 12345u;
static float noise(void)            /* uniform in [-1, 1) */
{
    lcg = lcg * 1664525u + 1013904223u;
    return ((lcg >> 8) / 8388608.0f) - 1.0f;
}

static void test_tone_found(void)
{
    static float x[N];
    for (int i = 0; i < N; i++) {
        float t = i / FS;
        x[i] = 0.2f * sinf(2.0f * (float)M_PI * 0.25f * t) + 0.5f * t / 30.0f + 0.02f * noise();
    }
    float bpm, conf;
    assert(dsp_breath_estimate(x, N, FS, &bpm, &conf));
    printf("tone: bpm=%.1f conf=%.2f\n", bpm, conf);
    assert(fabsf(bpm - 15.0f) <= 1.0f);
    assert(conf >= 0.5f);
}

static void test_noise_not_found(void)
{
    static float x[N];
    for (int i = 0; i < N; i++) x[i] = noise() + 0.5f * (i / FS) / 30.0f;
    float bpm, conf;
    assert(dsp_breath_estimate(x, N, FS, &bpm, &conf));
    printf("noise: bpm=%.1f conf=%.2f\n", bpm, conf);
    assert(conf < 0.2f);
}

/* Levels from a recorded capture (docs/SENSING.md, what was measured): 10 Hz bins of mean amplitude
 * had a white-ish std of 2.3% of the mean. A 2% breathing tone at that noise was found offline in
 * every window; the firmware estimator must show it too, and must not show the noise alone. */
static void test_recorded_levels(void)
{
    static float x[N], y[N];
    const float sd = 0.023f / 0.577f;          /* noise() has std 0.577 */
    for (int i = 0; i < N; i++) {
        float n = 1.0f + sd * noise();
        x[i] = n + 0.02f * sinf(2.0f * (float)M_PI * 0.25f * (i / FS));
        y[i] = n;
    }
    float bpm, conf, bpm0, conf0;
    assert(dsp_breath_estimate(x, N, FS, &bpm, &conf));
    assert(dsp_breath_estimate(y, N, FS, &bpm0, &conf0));
    printf("recorded levels: 2%% tone bpm=%.1f conf=%.2f, noise alone conf=%.2f\n", bpm, conf, conf0);
    assert(fabsf(bpm - 15.0f) <= 1.0f && conf >= 0.2f);
    assert(conf0 < 0.2f);
}

static void test_resample_hole(void)
{
    /* Samples at 0, 1, 2 s and 5 s; a 3 s hole between 2 s and 5 s. Interpolated inside the hole. */
    const int64_t t[4] = {0, 1000000, 2000000, 5000000};
    const float v[4] = {0.0f, 1.0f, 2.0f, 5.0f};
    float out[7];
    dsp_resample(v, t, 4, 0, 1000000, out, 7);
    for (int k = 0; k < 6; k++) assert(fabsf(out[k] - (float)k) < 1e-5f);
    assert(fabsf(out[6] - 5.0f) < 1e-5f);     /* held past the last sample */
    printf("resample: 0..6 s = %.1f %.1f %.1f %.1f %.1f %.1f %.1f\n",
           out[0], out[1], out[2], out[3], out[4], out[5], out[6]);
}

/* Nearness: distance, calibration floor and score. */
static void test_nearness(void)
{
    float mu[64], ref[64], s1[64] = {0}, s2[64] = {0};
    uint8_t base[64];
    uint64_t mask = 0;
    for (int k = 0; k < 64; k++) {
        base[k] = 128;                               /* flat baseline, 1.0 */
        if (k != 0 && !(k >= 27 && k <= 37)) mask |= 1ULL << k;
    }
    /* Distance: every masked subcarrier 0.05 off -> RMS 0.05; unmasked ones ignored. */
    for (int k = 0; k < 64; k++) mu[k] = (mask >> k & 1) ? (k % 2 ? 1.05f : 0.95f) : 9.0f;
    assert(fabsf(dsp_shape_rms(mu, base, mask) - 0.05f) < 1e-5f);
    assert(isnan(dsp_shape_rms(mu, base, 0)));

    /* Floor: ticks alternating +-0.02 around the baseline, sums kept relative to ref = 1.01. */
    for (int k = 0; k < 64; k++) ref[k] = 1.01f;
    for (int t = 0; t < 300; t++) {
        for (int k = 0; k < 64; k++) {
            float x = 1.0f + (t % 2 ? 0.02f : -0.02f) - ref[k];
            s1[k] += x;
            s2[k] += x * x;
        }
    }
    float fl = dsp_shape_floor(s1, s2, 300, ref, base, mask);
    printf("nearness: floor %.4f (want 0.0200)\n", fl);
    assert(fabsf(fl - 0.02f) < 1e-4f);
    assert(isnan(dsp_shape_floor(s1, s2, 0, ref, base, mask)));

    /* Score: 0 at or below the floor (empty room by construction), monotone, clamped. */
    assert(dsp_nearness(0.01f, 0.02f, 0.08f) == 0.0f);
    assert(dsp_nearness(0.02f, 0.02f, 0.08f) == 0.0f);
    assert(fabsf(dsp_nearness(0.06f, 0.02f, 0.08f) - 0.5f) < 1e-5f);
    assert(dsp_nearness(0.5f, 0.02f, 0.08f) == 1.0f);
    float prev = -1.0f;
    for (float d = 0.0f; d < 0.2f; d += 0.001f) {
        float s = dsp_nearness(d, 0.02f, 0.08f);
        assert(s >= prev && s >= 0.0f && s <= 1.0f);
        prev = s;
    }
    /* No baseline / no floor / no frames: not available, never a number. */
    assert(isnan(dsp_nearness(NAN, 0.02f, 0.08f)));
    assert(isnan(dsp_nearness(0.05f, NAN, 0.08f)));
    assert(isnan(dsp_nearness(0.05f, 0.02f, 0.0f)));
}

/* A frame of 64 subcarriers: amplitude a[k] (imag 0, real a[k]). */
static void frame(int8_t *iq, const float *a)
{
    for (int k = 0; k < 64; k++) { iq[2 * k] = 0; iq[2 * k + 1] = (int8_t)lrintf(a[k]); }
}

/* Feeds 60 s at 30 frames/s; shift(sec) moves the shape from second to second. Returns the ratio
 * of the last full bin. Per-frame noise is about 3 counts on 40, the level of the recording. */
static float motion_run(float step)
{
    static dsp_motion_t m;
    memset(&m, 0, sizeof(m));
    const uint8_t me[6] = {1, 2, 3, 4, 5, 6}, other[6] = {9, 9, 9, 9, 9, 9};
    int8_t iq[128];
    float a[64];
    for (int i = 0; i < 60 * 30; i++) {
        int64_t t = 1000000000LL + (int64_t)i * 1000000 / 30;
        int sec = i / 30;
        for (int k = 0; k < 64; k++) a[k] = 40.0f + 5.0f * noise() + step * ((sec * 7 + k) % 5 - 2);
        frame(iq, a);
        dsp_motion_frame(&m, iq, me, 1, t);
        dsp_motion_frame(&m, iq, me, 0, t);          /* legacy frames are ignored */
        if (i % 3 == 0) dsp_motion_frame(&m, iq, other, 1, t);   /* minority destination: ignored */
    }
    int64_t end = 1000000000LL + 60LL * 1000000;
    dsp_motion_advance(&m, end + 1);
    return dsp_motion_ratio(&m, (int32_t)(end / DSP_MOT_BIN_US) - 1);
}

static void test_motion(void)
{
    float still = motion_run(0.0f), moving = motion_run(3.0f);
    printf("motion: still ratio %.2f (score %.3f), moving ratio %.1f (score %.3f)\n", still,
           dsp_motion_score(still), moving, dsp_motion_score(moving));
    assert(still > 0.3f && still < 3.0f);     /* about 1 when nothing moves */
    assert(moving > 20.0f);
    /* Mapping: monotone, the default threshold 0.15 is ratio 6, no data is 0. */
    assert(fabsf(dsp_motion_score(6.0f) - 0.15f) < 1e-6f);
    assert(dsp_motion_score(NAN) == 0.0f && dsp_motion_score(1e6f) < 1.0f);
    for (float r = 0.0f; r < 100.0f; r += 0.5f) assert(dsp_motion_score(r + 0.5f) > dsp_motion_score(r));
    /* Too few frames: no ratio. */
    static dsp_motion_t m;
    int8_t iq[128];
    float a[64];
    for (int k = 0; k < 64; k++) a[k] = 40.0f;
    frame(iq, a);
    const uint8_t me[6] = {1};
    for (int i = 0; i < 40; i++) dsp_motion_frame(&m, iq, me, 1, 2000000000LL + i * 250000LL);   /* 4/s */
    dsp_motion_advance(&m, 2000000000LL + 20000000LL);
    assert(isnan(dsp_motion_ratio(&m, 200)));
}

static void test_sustain(void)
{
    dsp_sustain_t s = {0};
    assert(!dsp_sustain_push(&s, false));
    assert(!dsp_sustain_push(&s, true) && !dsp_sustain_push(&s, false));   /* 1 of 6: not yet */
    assert(!dsp_sustain_push(&s, true));                                    /* 2 of 6 */
    assert(dsp_sustain_push(&s, true));                                     /* 3 of 6: present */
    int held = 0;
    while (dsp_sustain_push(&s, false)) held++;
    printf("sustain: held %d bins after the first sustained bin\n", held);
    assert(held == 12);   /* 2 more bins still have 3 of 6, then 10: 12 bins from the start of the last one */
}

static void test_ble(void)
{
    static dsp_ble_t tab[DSP_BLE_N];
    const uint8_t dev[6] = {0xc0, 1, 2, 3, 4, 5}, mac[6] = {0xc0, 9, 9, 9, 9, 9};
    int h;
    /* A device near from the start (the computer itself) never counts. */
    for (uint32_t t = 100; t < 1000; t += 60) assert(dsp_ble_seen(tab, mac, -45, t, -55) == 0);
    /* Far for 10 min, then close: counts on the first strong advert. */
    for (uint32_t t = 100; t < 700; t += 120) assert(dsp_ble_seen(tab, dev, -80, t, -55) == 0);
    assert(dsp_ble_seen(tab, dev, -50, 760, -55) == 2);
    assert(dsp_ble_tick(tab, 800, &h) && h == 40);
    assert(dsp_ble_seen(tab, dev, -52, 880, -55) == 1);
    assert(dsp_ble_tick(tab, 880 + DSP_BLE_HOLD_S, &h) && h == DSP_BLE_HOLD_S);
    assert(!dsp_ble_tick(tab, 881 + DSP_BLE_HOLD_S, &h));    /* hold over */
    /* A passing crowd of new addresses does not push out a device heard for a while. */
    uint8_t a[6] = {0x40, 0, 0, 0, 0, 0};
    for (int i = 0; i < 200; i++) { a[5] = (uint8_t)i; dsp_ble_seen(tab, a, -70, 1100, -55); }
    dsp_ble_seen(tab, dev, -60, 1110, -55);
    int found = 0;
    for (int i = 0; i < DSP_BLE_N; i++) if (!memcmp(tab[i].addr, dev, 6) && (tab[i].flags & DSP_BLE_USED)) found = 1;
    assert(found);
    /* Expiry after the TTL. */
    assert(!dsp_ble_tick(tab, 1110 + DSP_BLE_TTL_S + 1, &h));
    for (int i = 0; i < DSP_BLE_N; i++) assert(!(tab[i].flags & DSP_BLE_USED));
    printf("ble cue: fires after an approach, holds %d s, keeps old entries, expires\n", DSP_BLE_HOLD_S);
}

int main(void)
{
    test_tone_found();
    test_noise_not_found();
    test_recorded_levels();
    test_resample_hole();
    test_nearness();
    test_motion();
    test_sustain();
    test_ble();
    printf("all sensing dsp cases pass\n");
    return 0;
}
