#pragma once
/* CTAP2 canonical CBOR pre-check (CTAP 2.1 §8 "CTAP2 canonical CBOR encoding form"), run on every
 * request before tinycbor touches it. Iterative: no recursion, so nesting cannot exhaust the stack.
 * Rejects: nesting deeper than CBOR_MAX_DEPTH, more than CBOR_MAX_ITEMS items, indefinite lengths,
 * tags, non-minimal integers and lengths, map keys that are not integers or strings, map keys out of
 * canonical order (which also rejects duplicates), truncation and trailing bytes.
 * Pure C with no IDF dependency, so it can be compiled and tested on the host. */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define CBOR_MAX_DEPTH 8
#define CBOR_MAX_ITEMS 512

/* Reads one head at p[*pos]. Returns false on truncation, reserved or indefinite length, non-minimal value. */
static bool cbc_head(const uint8_t *p, size_t len, size_t *pos, uint8_t *major, uint64_t *val)
{
    if (*pos >= len) return false;
    uint8_t ib = p[(*pos)++];
    *major = ib >> 5;
    uint8_t ai = ib & 0x1f;
    if (ai < 24) {
        *val = ai;
        return true;
    }
    if (ai > 27) return false;   /* 28..30 reserved, 31 indefinite length */
    size_t n = (size_t)1 << (ai - 24);
    if (len - *pos < n) return false;
    uint64_t v = 0;
    for (size_t i = 0; i < n; i++) v = (v << 8) | p[(*pos)++];
    *val = v;
    if (*major == 7) return true;   /* floats keep their size; simple values checked by the caller */
    /* Minimal encoding: the value must not fit a shorter form. */
    static const uint64_t min_for[4] = {24, 0x100, 0x10000, 0x100000000ull};
    return v >= min_for[ai - 24];
}

/* Canonical key order: shorter encoding first, then bytewise (CTAP 2.1 §8, keys of major types 0-3). */
static int cbc_keycmp(const uint8_t *a, size_t al, const uint8_t *b, size_t bl)
{
    if ((a[0] >> 5) != (b[0] >> 5)) return (a[0] >> 5) < (b[0] >> 5) ? -1 : 1;
    if (al != bl) return al < bl ? -1 : 1;
    return memcmp(a, b, al);
}

/* Returns true when p[0..len) is exactly one well-formed canonical CBOR item within the limits. */
static bool cbor_canonical_ok(const uint8_t *p, size_t len)
{
    struct {
        uint64_t left;      /* items still owed by this container */
        bool map;
        size_t prev_off;    /* previous key in this map, (0, 0) for none */
        size_t prev_len;
    } st[CBOR_MAX_DEPTH + 1];
    size_t depth = 0, pos = 0, items = 0;
    st[0].left = 1;   /* the root item */
    st[0].map = false;

    while (depth > 0 || st[0].left > 0) {
        if (st[depth].left == 0) {   /* container done */
            depth--;
            continue;
        }
        bool is_key = st[depth].map && (st[depth].left % 2 == 0);
        st[depth].left--;
        if (++items > CBOR_MAX_ITEMS) return false;

        size_t start = pos;
        uint8_t major;
        uint64_t v;
        if (!cbc_head(p, len, &pos, &major, &v)) return false;
        if (is_key && major > 3) return false;

        switch (major) {
        case 0:
        case 1:
            break;
        case 2:
        case 3:
            if (v > len - pos) return false;
            pos += (size_t)v;
            break;
        case 4:
        case 5: {
            if (depth == CBOR_MAX_DEPTH) return false;
            uint64_t n = (major == 5) ? v * 2 : v;
            if (v > len || n > len - pos) return false;   /* every item takes at least one byte */
            depth++;
            st[depth].left = n;
            st[depth].map = (major == 5);
            st[depth].prev_off = 0;
            st[depth].prev_len = 0;
            break;
        }
        case 6:
            return false;   /* tags MUST NOT be present */
        default: {          /* 7: false, true, null, undefined, floats */
            uint8_t ai = p[start] & 0x1f;
            if (ai < 20 || ai == 24) return false;   /* unassigned simple values */
            break;
        }
        }

        if (is_key) {
            size_t klen = pos - start;
            if (st[depth].prev_len && cbc_keycmp(p + st[depth].prev_off, st[depth].prev_len, p + start, klen) >= 0) {
                return false;   /* out of order or duplicate */
            }
            st[depth].prev_off = start;
            st[depth].prev_len = klen;
        }
    }
    return pos == len;
}
