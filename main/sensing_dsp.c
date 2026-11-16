#include "sensing_dsp.h"

#include <math.h>

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
