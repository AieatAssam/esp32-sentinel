#pragma once

#include <stdbool.h>
#include <stdint.h>

/* Sends the lock-screen shortcut for config lock_os over the keyboard HID interface.
 * Returns true only when both the press and the release reports were queued to the host.
 * Returns false (nothing typed) when the keyboard is not enumerated or the bus is suspended. */
bool lock_send(void);

/* ---------- auto-lock retry policy (pure; tools/lock_policy_test.c) ----------
 * One lock per away period. The lock counts as done only when lock_send() succeeded; a failed
 * attempt (keyboard not ready, bus suspended) is retried every LOCK_RETRY_US while still away.
 * Enabling autolock while already away locks at the next tick, because nothing was sent yet.
 * USB suspend: the device has no remote wakeup, so a sleeping host cannot be reached. Retries go
 * on while away; if the host resumes and the room is still empty, the lock goes out within
 * LOCK_RETRY_US of the resume. If presence returns first, the pending lock is dropped. */
#define LOCK_RETRY_US (2LL * 1000000)

typedef struct {
    bool sent;            /* a lock went out in this away period */
    int64_t next_try_us;  /* earliest time for the next attempt */
} lock_policy_t;

/* Call every tick. Returns true when a lock attempt should be made now. */
static inline bool lock_policy_due(lock_policy_t *p, bool away, bool autolock, int64_t now_us)
{
    if (!away) {
        p->sent = false;
        p->next_try_us = 0;
        return false;
    }
    return autolock && !p->sent && now_us >= p->next_try_us;
}

/* Records the outcome of an attempt made because lock_policy_due() returned true. */
static inline void lock_policy_result(lock_policy_t *p, bool ok, int64_t now_us)
{
    if (ok) p->sent = true;
    else p->next_try_us = now_us + LOCK_RETRY_US;
}
