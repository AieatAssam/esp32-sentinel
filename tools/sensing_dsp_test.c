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

int main(void)
{
    test_tone_found();
    test_noise_not_found();
    test_recorded_levels();
    test_resample_hole();
    printf("all sensing dsp cases pass\n");
    return 0;
}
