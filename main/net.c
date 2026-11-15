#include "net.h"

#include <stdlib.h>
#include <string.h>
#include "esp_event.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_netif.h"
#include "esp_netif_ip_addr.h"
#include "lwip/esp_netif_net_stack.h"
#include "lwip/ip4_addr.h"
#include "apps/dhcpserver/dhcpserver.h"
#include "apps/dhcpserver/dhcpserver_options.h"
#include "tinyusb_net.h"

static const char *TAG = "net";

static esp_netif_t *s_netif = NULL;

/* First LOG_FRAMES frames each way are logged with length and EtherType, so a dead
 * link shows which direction stops. Counters are only touched by one task each
 * (rx: TinyUSB task, tx: lwIP task). */
#define LOG_FRAMES 8
static unsigned s_rx_n, s_tx_n, s_tx_err;

/* Called on USB mount so pre-mount tx failures (ESP_ERR_INVALID_STATE) do not use up
 * the log slots meant for the first real frames. */
void net_usb_mounted(void)
{
    s_tx_n = 0;
    s_tx_err = 0;
}

static unsigned ethertype(const void *frame, size_t len)
{
    const uint8_t *p = frame;
    return len >= 14 ? ((unsigned)p[12] << 8) | p[13] : 0;
}

static esp_err_t netif_transmit(void *h, void *buffer, size_t len)
{
    (void)h;
    /* Synchronous send copies out of the buffer before returning, so lwIP can free it.
     * Before the host mounts the device this returns ESP_ERR_INVALID_STATE. */
    esp_err_t err = tinyusb_net_send_sync(buffer, (uint16_t)len, NULL, pdMS_TO_TICKS(100));
    if (++s_tx_n <= LOG_FRAMES) {
        ESP_LOGI(TAG, "tx #%u len %u type 0x%04x: %s", s_tx_n, (unsigned)len, ethertype(buffer, len),
                 esp_err_to_name(err));
    }
    /* Every error up to 20, then every 100th, so a stuck link cannot flood the ring. */
    if (err != ESP_OK && (++s_tx_err <= 20 || s_tx_err % 100 == 0)) {
        ESP_LOGW(TAG, "tx error %u: %s (len %u)", s_tx_err, esp_err_to_name(err), (unsigned)len);
    }
    return err;
}

static void netif_free_rx(void *h, void *buffer)
{
    (void)h;
    free(buffer);
}

/* USB -> lwIP. TinyUSB reuses its buffer, so copy and hand the copy to lwIP. */
esp_err_t net_usb_rx(void *buffer, uint16_t len, void *ctx)
{
    (void)ctx;
    if (++s_rx_n <= LOG_FRAMES) {
        ESP_LOGI(TAG, "rx #%u len %u type 0x%04x%s", s_rx_n, (unsigned)len, ethertype(buffer, len),
                 s_netif ? "" : " (no netif, dropped)");
    }
    if (!s_netif) return ESP_OK;
    void *copy = malloc(len);
    if (!copy) return ESP_ERR_NO_MEM;
    memcpy(copy, buffer, len);
    /* On every path, ethernetif_input() owns the buffer: it frees it through
     * netif_free_rx() on error too. Freeing here again was a double free (TinyUSB task
     * panic, tlsf_free "block already marked as free"). */
    return esp_netif_receive(s_netif, copy, len, NULL);
}

static void on_ip_event(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    (void)arg; (void)base;
    if (id == IP_EVENT_ASSIGNED_IP_TO_CLIENT) {
        const ip_event_assigned_ip_to_client_t *e = data;
#if CONFIG_DEV_BACKDOOR
        ESP_LOGI(TAG, "DHCP lease " IPSTR " to " MACSTR, IP2STR(&e->ip), MAC2STR(e->mac));
#else
        ESP_LOGI(TAG, "DHCP lease " IPSTR, IP2STR(&e->ip));   /* no host MAC in release logs */
#endif
    }
}

esp_err_t net_init(void)
{
    uint8_t base[6];
    esp_err_t err = esp_read_mac(base, ESP_MAC_WIFI_STA);
    if (err != ESP_OK) return err;
    /* lwIP side of the link; differs from the NCM device MAC set in usb_init(). */
    uint8_t lwip_mac[6] = {0x02, base[1], base[2], base[3], base[4], base[5] ^ 0x01};

    static esp_netif_ip_info_t ip_info;
    ip_info.ip.addr = ESP_IP4TOADDR(192, 168, 7, 1);
    ip_info.netmask.addr = ESP_IP4TOADDR(255, 255, 255, 0);
    ip_info.gw.addr = 0;   /* no default route: the host must not send internet traffic here */

    esp_netif_inherent_config_t base_cfg = {
        /* AUTOUP is required: without it esp_netif_action_start() never calls
         * netif_set_up(), so the DHCP server is never started and ethernetif_input()
         * drops every received frame. This was the dead-link bug. */
        .flags = ESP_NETIF_DHCP_SERVER | ESP_NETIF_FLAG_AUTOUP,
        .ip_info = &ip_info,
        .if_key = "USB_NCM",
        .if_desc = "usb ncm",
        .route_prio = 10,
    };
    esp_netif_driver_ifconfig_t driver_cfg = {
        .handle = (void *)1,   /* static singleton, must be non-NULL */
        .transmit = netif_transmit,
        .driver_free_rx_buffer = netif_free_rx,
    };
    struct esp_netif_netstack_config lwip_cfg = {
        .lwip = {
            .init_fn = ethernetif_init,
            .input_fn = ethernetif_input,
        },
    };
    esp_netif_config_t cfg = {
        .base = &base_cfg,
        .driver = &driver_cfg,
        .stack = &lwip_cfg,
    };

    s_netif = esp_netif_new(&cfg);
    if (!s_netif) return ESP_FAIL;
    esp_netif_set_mac(s_netif, lwip_mac);

    /* Withdraw router and DNS from the DHCP offer. The option value is one byte
     * (dhcps_offer_t, 0 = neither flag) and the server must still be stopped here.
     * A failure is logged, not fatal: the device must stay reachable. The host check
     * (no router/DNS in the offer) is the real test. */
    dhcps_offer_t offer = 0;
    esp_err_t e_router = esp_netif_dhcps_option(s_netif, ESP_NETIF_OP_SET, ROUTER_SOLICITATION_ADDRESS,
                                                &offer, sizeof(offer));
    esp_err_t e_dns = esp_netif_dhcps_option(s_netif, ESP_NETIF_OP_SET, DOMAIN_NAME_SERVER,
                                             &offer, sizeof(offer));
    if (e_router != ESP_OK || e_dns != ESP_OK) {
        ESP_LOGE(TAG, "dhcps offer flags not set: router %s, dns %s", esp_err_to_name(e_router),
                 esp_err_to_name(e_dns));
    }

    /* Lease pool 192.168.7.2..192.168.7.3. lwIP rejects a one-address pool (start must be
     * below end), so the host gets the first free address: .2. */
    dhcps_lease_t lease = {.enable = true};
    IP4_ADDR(&lease.start_ip, 192, 168, 7, 2);
    IP4_ADDR(&lease.end_ip, 192, 168, 7, 3);
    err = esp_netif_dhcps_option(s_netif, ESP_NETIF_OP_SET, ESP_NETIF_REQUESTED_IP_ADDRESS,
                                 &lease, sizeof(lease));
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "dhcps lease pool not set: %s", esp_err_to_name(err));
    }

    esp_event_handler_register(IP_EVENT, IP_EVENT_ASSIGNED_IP_TO_CLIENT, on_ip_event, NULL);

    esp_netif_action_start(s_netif, 0, 0, 0);
    /* IPv6 link-local, so `ping6 fe80::...%<if>` works as a second probe. */
    esp_err_t e6 = esp_netif_create_ip6_linklocal(s_netif);

    esp_netif_dhcp_status_t dhcps = ESP_NETIF_DHCP_INIT;
    esp_netif_dhcps_get_status(s_netif, &dhcps);
    bool up = esp_netif_is_netif_up(s_netif);
    ESP_LOGI(TAG, "USB netif 192.168.7.1/24 %s, DHCP server %s, ip6 ll %s, lwip MAC " MACSTR,
             up ? "UP" : "DOWN", dhcps == ESP_NETIF_DHCP_STARTED ? "started" : "NOT started",
             esp_err_to_name(e6), MAC2STR(lwip_mac));
    if (!up || dhcps != ESP_NETIF_DHCP_STARTED) {
        ESP_LOGE(TAG, "USB netif not usable (up=%d, dhcps status=%d)", up, (int)dhcps);
        return ESP_FAIL;
    }
    return ESP_OK;
}
