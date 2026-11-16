/* Host checks for main/sensing_dsp.c. Build and run (binary in the scratchpad):
 *   cc -Wall -Werror -I main tools/sensing_dsp_test.c main/sensing_dsp.c -lm -o <scratchpad>/sensing_dsp_test
 * Exit 0 when every case holds; asserts otherwise. */
#include <assert.h>
#include <math.h>
#include <stdio.h>
#include <stdint.h>

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

int main(void)
{
    test_tone_found();
    test_noise_not_found();
    test_recorded_levels();
    test_resample_hole();
    test_nearness();
    printf("all sensing dsp cases pass\n");
    return 0;
}
