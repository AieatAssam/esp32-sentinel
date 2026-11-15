#pragma once

/* Pure network policy checks for the USB-only HTTP server and joined mode. No ESP-IDF headers,
 * so tools/net_policy_test.c builds it on the host. All addresses are byte arrays in network
 * order (an lwIP ip4_addr_t memcpy'd into 4 bytes gives exactly this). */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

static const uint8_t NET_POLICY_USB4[4] = {192, 168, 7, 1};
static const uint8_t NET_POLICY_USB_MASK[4] = {255, 255, 255, 0};
static const uint8_t NET_POLICY_MAPPED_PREFIX[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};

/* Reduces a socket address to its IPv4 bytes: a 4-byte address, or an IPv4-mapped IPv6 address.
 * Returns NULL for anything else (native IPv6 is never served). */
static inline const uint8_t *net_policy_v4(const uint8_t *addr, int len)
{
    if (len == 4) return addr;
    if (len == 16 && memcmp(addr, NET_POLICY_MAPPED_PREFIX, 12) == 0) return addr + 12;
    return NULL;
}

/* Local addresses the HTTP server may answer on: the USB netif (192.168.7.1), as IPv4 or as an
 * IPv4-mapped IPv6 address. Any other local address (the joined Wi-Fi station, loopback, link-local)
 * is refused. addr is in network byte order: 4 bytes for IPv4, 16 bytes for IPv6. */
static inline bool net_policy_local_addr_allowed(const uint8_t *addr, int len)
{
    const uint8_t *v4 = net_policy_v4(addr, len);
    return v4 && memcmp(v4, NET_POLICY_USB4, 4) == 0;
}

/* Peers the HTTP server may answer: a host address on the USB link, 192.168.7.2..192.168.7.254.
 * The network, broadcast and the device's own address are refused. */
static inline bool net_policy_peer_allowed(const uint8_t *addr, int len)
{
    const uint8_t *v4 = net_policy_v4(addr, len);
    if (!v4 || v4[0] != 192 || v4[1] != 168 || v4[2] != 7) return false;
    return v4[3] >= 2 && v4[3] <= 254;
}

/* True when a joined-mode station lease (address, netmask, gateway) overlaps the USB link
 * 192.168.7.0/24 in any way. Such a lease would give the station a route or an address on the USB
 * subnet, so the station could then receive connections meant for the USB link. Two subnets
 * overlap when they agree under the shorter of the two masks. A gateway inside 192.168.7.0/24 is
 * a conflict too. A zero mask counts as the whole address space (conflicts). */
static inline bool net_policy_lease_conflicts(const uint8_t ip[4], const uint8_t mask[4], const uint8_t gw[4])
{
    bool same = true;
    for (int i = 0; i < 4; i++) {
        uint8_t m = mask[i] & NET_POLICY_USB_MASK[i];
        if ((ip[i] & m) != (NET_POLICY_USB4[i] & m)) same = false;
    }
    if (same) return true;
    static const uint8_t zero[4] = {0, 0, 0, 0};
    if (memcmp(gw, zero, 4) == 0) return false;
    return gw[0] == 192 && gw[1] == 168 && gw[2] == 7;
}

/* Host header allowlist: exactly the device address, with or without :80. Anything else (a DNS
 * name rebound to 192.168.7.1, an empty Host) is refused. */
static inline bool net_policy_host_ok(const char *host)
{
    return host && (strcmp(host, "192.168.7.1") == 0 || strcmp(host, "192.168.7.1:80") == 0);
}
