/* Host check for main/net_policy.h. Build and run:
 *   cc -Wall -Werror -I main tools/net_policy_test.c -o /tmp/net_policy_test && /tmp/net_policy_test
 * Exit 0 when every case holds. */
#include <assert.h>
#include <stdio.h>

#include "net_policy.h"

static int failures;

static void expect(const char *name, const uint8_t *addr, int len, bool want)
{
    bool got = net_policy_local_addr_allowed(addr, len);
    if (got != want) {
        printf("FAIL %s: got %d want %d\n", name, got, want);
        failures++;
    } else {
        printf("ok   %s\n", name);
    }
}

static void check(const char *name, bool got, bool want)
{
    printf("%s %s\n", got == want ? "ok  " : "FAIL", name);
    if (got != want) failures++;
}

int main(void)
{
    const uint8_t usb[4] = {192, 168, 7, 1};
    const uint8_t usb_other[4] = {192, 168, 7, 2};
    const uint8_t ten[4] = {10, 0, 0, 1};
    const uint8_t loop[4] = {127, 0, 0, 1};
    const uint8_t sta[4] = {192, 168, 1, 50};
    const uint8_t mapped_usb[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 7, 1};
    const uint8_t mapped_ten[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 1};
    const uint8_t linklocal[16] = {0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    const uint8_t v6_any[16] = {0};

    expect("v4 192.168.7.1 accepted", usb, 4, true);
    expect("v4 10.0.0.1 refused", ten, 4, false);
    expect("v4 192.168.7.2 refused", usb_other, 4, false);
    expect("v4 loopback refused", loop, 4, false);
    expect("v4 STA address 192.168.1.50 refused", sta, 4, false);
    expect("v4-mapped 192.168.7.1 accepted", mapped_usb, 16, true);
    expect("v4-mapped 10.0.0.1 refused", mapped_ten, 16, false);
    expect("fe80::1 link-local refused", linklocal, 16, false);
    expect(":: refused", v6_any, 16, false);
    expect("bad length refused", usb, 3, false);

    /* peers: only hosts on the USB link */
    const uint8_t net0[4] = {192, 168, 7, 0}, bcast[4] = {192, 168, 7, 255};
    const uint8_t mapped_host[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 7, 2};
    check("peer 192.168.7.2 accepted", net_policy_peer_allowed(usb_other, 4), true);
    check("peer v4-mapped 192.168.7.2 accepted", net_policy_peer_allowed(mapped_host, 16), true);
    check("peer 192.168.7.1 (self) refused", net_policy_peer_allowed(usb, 4), false);
    check("peer 192.168.7.0 refused", net_policy_peer_allowed(net0, 4), false);
    check("peer 192.168.7.255 refused", net_policy_peer_allowed(bcast, 4), false);
    check("peer STA 192.168.1.50 refused", net_policy_peer_allowed(sta, 4), false);
    check("peer fe80::1 refused", net_policy_peer_allowed(linklocal, 16), false);

    /* station leases */
    const uint8_t m24[4] = {255, 255, 255, 0}, m16[4] = {255, 255, 0, 0}, m25[4] = {255, 255, 255, 128};
    const uint8_t m0[4] = {0, 0, 0, 0};
    const uint8_t gw1[4] = {192, 168, 1, 1}, gw7[4] = {192, 168, 7, 254}, gw0[4] = {0, 0, 0, 0};
    const uint8_t ip_rogue[4] = {192, 168, 7, 1}, ip_7_50[4] = {192, 168, 7, 50}, ip_6_50[4] = {192, 168, 6, 50};
    const uint8_t ip_hi[4] = {192, 168, 7, 200};
    check("lease 192.168.1.50/24 gw .1.1 ok", net_policy_lease_conflicts(sta, m24, gw1), false);
    check("lease 10.0.0.1/24 no gw ok", net_policy_lease_conflicts(ten, m24, gw0), false);
    check("lease 192.168.7.1/24 (rogue) conflicts", net_policy_lease_conflicts(ip_rogue, m24, gw1), true);
    check("lease 192.168.7.50/24 conflicts", net_policy_lease_conflicts(ip_7_50, m24, gw1), true);
    check("lease 192.168.7.200/25 conflicts", net_policy_lease_conflicts(ip_hi, m25, gw1), true);
    check("lease 192.168.6.50/16 covers .7 conflicts", net_policy_lease_conflicts(ip_6_50, m16, gw1), true);
    check("lease 192.168.6.50/24 ok", net_policy_lease_conflicts(ip_6_50, m24, gw1), false);
    check("lease 192.168.6.50/24 gw in .7 conflicts", net_policy_lease_conflicts(ip_6_50, m24, gw7), true);
    check("lease with /0 mask conflicts", net_policy_lease_conflicts(ten, m0, gw0), true);

    /* Host header */
    check("host 192.168.7.1", net_policy_host_ok("192.168.7.1"), true);
    check("host 192.168.7.1:80", net_policy_host_ok("192.168.7.1:80"), true);
    check("host rebind name refused", net_policy_host_ok("evil.example"), false);
    check("host 192.168.7.1:8080 refused", net_policy_host_ok("192.168.7.1:8080"), false);
    check("host prefix trick refused", net_policy_host_ok("192.168.7.1.evil.example"), false);
    check("host empty refused", net_policy_host_ok(""), false);
    check("host NULL refused", net_policy_host_ok(NULL), false);

    assert(failures == 0);
    if (failures) {
        printf("%d failure(s)\n", failures);
        return 1;
    }
    printf("all net policy cases pass\n");
    return 0;
}
