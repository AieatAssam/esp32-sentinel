/* Host check for the auto-lock retry policy in main/lock.h. Build and run:
 *   cc -Wall -Werror -I main tools/lock_policy_test.c -o /tmp/lock_policy_test && /tmp/lock_policy_test
 * (lock.h's lock_send() is only declared, never called here.) Exit 0 on success. */
#include <assert.h>
#include <stdio.h>

#include "lock.h"

#define S 1000000LL

int main(void)
{
    lock_policy_t p = {0};

    /* present: never due */
    assert(!lock_policy_due(&p, false, true, 1 * S));

    /* away with autolock: due once; success latches */
    assert(lock_policy_due(&p, true, true, 2 * S));
    lock_policy_result(&p, true, 2 * S);
    assert(!lock_policy_due(&p, true, true, 3 * S));
    assert(!lock_policy_due(&p, true, true, 100 * S));

    /* presence returns, then away again: one more lock */
    assert(!lock_policy_due(&p, false, true, 101 * S));
    assert(lock_policy_due(&p, true, true, 102 * S));
    lock_policy_result(&p, true, 102 * S);

    /* failed send (keyboard not ready / suspended): retried after 2 s, not before */
    p = (lock_policy_t){0};
    assert(lock_policy_due(&p, true, true, 10 * S));
    lock_policy_result(&p, false, 10 * S);
    assert(!lock_policy_due(&p, true, true, 11 * S));
    assert(lock_policy_due(&p, true, true, 12 * S));
    lock_policy_result(&p, false, 12 * S);
    assert(lock_policy_due(&p, true, true, 14 * S));
    lock_policy_result(&p, true, 14 * S);
    assert(!lock_policy_due(&p, true, true, 16 * S));

    /* pending retry dropped when presence returns first */
    p = (lock_policy_t){0};
    assert(lock_policy_due(&p, true, true, 20 * S));
    lock_policy_result(&p, false, 20 * S);
    assert(!lock_policy_due(&p, false, true, 21 * S));
    assert(!lock_policy_due(&p, false, true, 30 * S));

    /* L6: autolock enabled while already away locks at the next tick */
    p = (lock_policy_t){0};
    assert(!lock_policy_due(&p, true, false, 40 * S));
    assert(!lock_policy_due(&p, true, false, 50 * S));
    assert(lock_policy_due(&p, true, true, 51 * S));
    lock_policy_result(&p, true, 51 * S);
    /* toggling off and on in the same away period does not lock twice */
    assert(!lock_policy_due(&p, true, false, 52 * S));
    assert(!lock_policy_due(&p, true, true, 53 * S));

    printf("all lock policy cases pass\n");
    return 0;
}
