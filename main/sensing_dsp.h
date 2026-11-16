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
