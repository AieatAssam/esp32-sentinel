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
