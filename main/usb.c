#include "usb.h"

#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "tinyusb.h"
#include "tinyusb_net.h"
#include "tinyusb_default_config.h"
#include "tusb.h"
#include "usb_fido.h"

static const char *TAG = "usb";

/* Interfaces: 0-1 NCM (control, data), 2 FIDO HID, 3 keyboard HID. */
enum {
    ITF_NUM_NET = 0,
    ITF_NUM_FIDO = 2,
    ITF_NUM_KBD = 3,
    ITF_NUM_TOTAL = 4,
};

/* HID instances follow interface order in the configuration descriptor. */
#define HID_INST_FIDO 0
#define HID_INST_KBD  1

/* Endpoints: IN 0x81 notif, 0x82 NCM data in, 0x83 FIDO in, 0x84 keyboard in;
 * OUT 0x02 NCM data out, 0x03 FIDO out. ESP32-S3 has 5 IN + 5 OUT besides EP0. */
#define EPNUM_NET_NOTIF 0x01
#define EPNUM_NET_DATA  0x02
#define EPNUM_FIDO      0x03
#define EPNUM_KBD       0x04

/* String table. tinyusb_net_init() writes its MAC string into index
 * tusb_get_mac_string_id(), which is 5 when only NCM is enabled (esp_tinyusb
 * usb_descriptors.c STRID enum). So NET_IF must be 4 and MAC 5, or it overwrites
 * whatever string sits at 5 (it used to rename the FIDO interface). */
enum {
    STRID_LANGID = 0,
    STRID_MANUFACTURER,
    STRID_PRODUCT,
    STRID_SERIAL,
    STRID_NET_IF,
    STRID_MAC,
    STRID_FIDO_IF,
    STRID_KBD_IF,
    STRID_COUNT,
};
_Static_assert(STRID_MAC == 5, "must match esp_tinyusb tusb_get_mac_string_id() for NCM-only");

static const tusb_desc_device_t s_dev_desc = {
    .bLength = sizeof(tusb_desc_device_t),
    .bDescriptorType = TUSB_DESC_DEVICE,
    .bcdUSB = 0x0200,
    .bDeviceClass = TUSB_CLASS_MISC,
    .bDeviceSubClass = 0x02,      /* MISC_SUBCLASS_COMMON (IAD) */
    .bDeviceProtocol = 0x01,      /* MISC_PROTOCOL_IAD */
    .bMaxPacketSize0 = 64,
    .idVendor = 0x303A,           /* Espressif */
    .idProduct = 0x4001,          /* Espressif development range */
    .bcdDevice = 0x0100,
    .iManufacturer = STRID_MANUFACTURER,
    .iProduct = STRID_PRODUCT,
    .iSerialNumber = STRID_SERIAL,
    .bNumConfigurations = 1,
};

/* FIDO CTAPHID report descriptor: usage page 0xF1D0, usage 0x01, 64-byte IN/OUT, no report ID. */
static const uint8_t s_fido_report_desc[] = {
    0x06, 0xD0, 0xF1,   /* Usage Page (FIDO) */
    0x09, 0x01,         /* Usage (CTAPHID) */
    0xA1, 0x01,         /* Collection (Application) */
    0x09, 0x20,         /*   Usage (Input Report Data) */
    0x15, 0x00,         /*   Logical Minimum (0) */
    0x26, 0xFF, 0x00,   /*   Logical Maximum (255) */
    0x75, 0x08,         /*   Report Size (8) */
    0x95, 0x40,         /*   Report Count (64) */
    0x81, 0x02,         /*   Input (Data, Var, Abs) */
    0x09, 0x21,         /*   Usage (Output Report Data) */
    0x15, 0x00,
    0x26, 0xFF, 0x00,
    0x75, 0x08,
    0x95, 0x40,
    0x91, 0x02,         /*   Output (Data, Var, Abs) */
    0xC0,               /* End Collection */
};

/* Standard boot keyboard report descriptor (8-byte input report, LED output). */
static const uint8_t s_kbd_report_desc[] = {
    0x05, 0x01, 0x09, 0x06, 0xA1, 0x01,
    0x05, 0x07, 0x19, 0xE0, 0x29, 0xE7, 0x15, 0x00, 0x25, 0x01, 0x75, 0x01, 0x95, 0x08, 0x81, 0x02,
    0x95, 0x01, 0x75, 0x08, 0x81, 0x01,
    0x95, 0x05, 0x75, 0x01, 0x05, 0x08, 0x19, 0x01, 0x29, 0x05, 0x91, 0x02,
    0x95, 0x01, 0x75, 0x03, 0x91, 0x01,
    0x95, 0x06, 0x75, 0x08, 0x15, 0x00, 0x25, 0x65, 0x05, 0x07, 0x19, 0x00, 0x29, 0x65, 0x81, 0x00,
    0xC0,
};

#define CFG_TOTAL_LEN (9 + TUD_CDC_NCM_DESC_LEN + TUD_HID_INOUT_DESC_LEN + TUD_HID_DESC_LEN)

static const uint8_t s_cfg_desc[] = {
    TUD_CONFIG_DESCRIPTOR(1, ITF_NUM_TOTAL, 0, CFG_TOTAL_LEN, 0x80, 100),
    /* NCM: control iface, string for interface name, MAC string, notif EP, data EP, 1514 max segment */
    TUD_CDC_NCM_DESCRIPTOR(ITF_NUM_NET, STRID_NET_IF, STRID_MAC,
                           (0x80 | EPNUM_NET_NOTIF), 64, EPNUM_NET_DATA, (0x80 | EPNUM_NET_DATA), 64, 1514),
    /* FIDO: interrupt IN and OUT, 64 bytes, boot protocol off */
    TUD_HID_INOUT_DESCRIPTOR(ITF_NUM_FIDO, STRID_FIDO_IF, 0, sizeof(s_fido_report_desc),
                             EPNUM_FIDO, (0x80 | EPNUM_FIDO), 64, 5),
    /* Boot keyboard: interrupt IN, 8 bytes */
    TUD_HID_DESCRIPTOR(ITF_NUM_KBD, STRID_KBD_IF, 1, sizeof(s_kbd_report_desc),
                       (0x80 | EPNUM_KBD), 8, 10),
};

static char s_serial[13];
static char s_mac_str[13];
static const char *s_strings[STRID_COUNT];

static bool s_kbd_ready_logged = false;

/* ---- TinyUSB class callbacks ---- */

uint8_t const *tud_hid_descriptor_report_cb(uint8_t instance)
{
    return instance == HID_INST_FIDO ? s_fido_report_desc : s_kbd_report_desc;
}

uint16_t tud_hid_get_report_cb(uint8_t instance, uint8_t report_id, hid_report_type_t report_type,
                               uint8_t *buffer, uint16_t reqlen)
{
    (void)instance; (void)report_id; (void)report_type; (void)buffer; (void)reqlen;
    return 0;
}

void tud_hid_set_report_cb(uint8_t instance, uint8_t report_id, hid_report_type_t report_type,
                           uint8_t const *buffer, uint16_t bufsize)
{
    (void)report_id;
    if (instance == HID_INST_FIDO && report_type == HID_REPORT_TYPE_OUTPUT) {
        usb_fido_on_out(buffer, bufsize);
    }
}

/* ---- keyboard ---- */

static SemaphoreHandle_t s_kbd_mux;      /* serialises taps (sensing task, httpd) */
static StaticSemaphore_t s_kbd_mux_buf;
static bool s_kbd_up_pending;            /* a press went out but its release did not */

/* Queues one keyboard report, waiting up to timeout_ms for the IN endpoint to be free.
 * Fails at once when the bus is suspended or the keyboard is not enumerated. */
static bool kbd_report(const uint8_t r[8], int timeout_ms)
{
    TickType_t start = xTaskGetTickCount();
    for (;;) {
        if (!tud_ready()) return false;                       /* unmounted or suspended */
        if (tud_hid_n_ready(HID_INST_KBD)) return tud_hid_n_report(HID_INST_KBD, 0, r, 8);
        if (xTaskGetTickCount() - start >= pdMS_TO_TICKS(timeout_ms)) return false;
        vTaskDelay(1);                                        /* one tick: 10 ms at 100 Hz */
    }
}

bool usb_keyboard_tap(uint8_t modifiers, uint8_t keycode)
{
    static const uint8_t up[8] = {0};
    if (!s_kbd_mux || xSemaphoreTake(s_kbd_mux, pdMS_TO_TICKS(500)) != pdTRUE) return false;
    /* A release that could not be sent last time goes first, so no modifier stays held. */
    if (s_kbd_up_pending && kbd_report(up, 100)) s_kbd_up_pending = false;
    bool ok = false;
    uint8_t down[8] = {modifiers, 0, keycode, 0, 0, 0, 0, 0};
    if (!s_kbd_up_pending && kbd_report(down, 100)) {
        if (!s_kbd_ready_logged) {
            s_kbd_ready_logged = true;
            ESP_LOGI(TAG, "keyboard interface ready");
        }
        vTaskDelay(pdMS_TO_TICKS(20));
        ok = kbd_report(up, 1000);
        s_kbd_up_pending = !ok;
    }
    xSemaphoreGive(s_kbd_mux);
    if (!ok) ESP_LOGW(TAG, "keyboard report not delivered%s", s_kbd_up_pending ? " (release pending)" : "");
    return ok;
}

/* ---- USB bus events (TinyUSB task) ---- */

static void usb_event_cb(tinyusb_event_t *event, void *arg)
{
    (void)arg;
    switch (event->id) {
    case TINYUSB_EVENT_ATTACHED:  ESP_LOGI(TAG, "USB mounted by host"); net_usb_mounted(); break;
    case TINYUSB_EVENT_DETACHED:  ESP_LOGW(TAG, "USB unmounted"); break;
#ifdef CONFIG_TINYUSB_SUSPEND_CALLBACK
    case TINYUSB_EVENT_SUSPENDED: ESP_LOGW(TAG, "USB suspended"); break;
#endif
#ifdef CONFIG_TINYUSB_RESUME_CALLBACK
    case TINYUSB_EVENT_RESUMED:   ESP_LOGI(TAG, "USB resumed"); break;
#endif
    default:                      ESP_LOGI(TAG, "USB event %d", (int)event->id); break;
    }
}

/* ---- init ---- */

esp_err_t usb_init(void)
{
    s_kbd_mux = xSemaphoreCreateMutexStatic(&s_kbd_mux_buf);
    uint8_t base[6];
    esp_err_t err = esp_read_mac(base, ESP_MAC_WIFI_STA);
    if (err != ESP_OK) return err;

    /* NCM device MAC: locally administered, derived from the chip MAC. */
    uint8_t ncm_mac[6] = {0x02, base[1], base[2], base[3], base[4], base[5]};
    snprintf(s_serial, sizeof(s_serial), "%02X%02X%02X%02X%02X%02X",
             base[0], base[1], base[2], base[3], base[4], base[5]);
    snprintf(s_mac_str, sizeof(s_mac_str), "%02X%02X%02X%02X%02X%02X",
             ncm_mac[0], ncm_mac[1], ncm_mac[2], ncm_mac[3], ncm_mac[4], ncm_mac[5]);

    s_strings[STRID_LANGID] = "\x09\x04";
    s_strings[STRID_MANUFACTURER] = "Espressif";
    s_strings[STRID_PRODUCT] = "S3 Sentinel";
    s_strings[STRID_SERIAL] = s_serial;
    s_strings[STRID_NET_IF] = "Sentinel Network";
    s_strings[STRID_FIDO_IF] = "Sentinel FIDO";
    s_strings[STRID_KBD_IF] = "Sentinel Keyboard";
    s_strings[STRID_MAC] = s_mac_str;

    tinyusb_config_t tcfg = TINYUSB_DEFAULT_CONFIG();
    tcfg.descriptor.device = &s_dev_desc;
    tcfg.descriptor.qualifier = NULL;
    tcfg.descriptor.string = s_strings;
    tcfg.descriptor.string_count = STRID_COUNT;
    tcfg.descriptor.full_speed_config = s_cfg_desc;
    tcfg.descriptor.high_speed_config = NULL;
    tcfg.event_cb = usb_event_cb;
    err = tinyusb_driver_install(&tcfg);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "tinyusb_driver_install failed: %s", esp_err_to_name(err));
        return err;
    }

    tinyusb_net_config_t ncfg = {
        .on_recv_callback = net_usb_rx,
    };
    memcpy(ncfg.mac_addr, ncm_mac, sizeof(ncm_mac));
    err = tinyusb_net_init(&ncfg);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "tinyusb_net_init failed: %s", esp_err_to_name(err));
        return err;
    }
    ESP_LOGI(TAG, "USB composite up (NCM MAC %s)", s_mac_str);
    return ESP_OK;
}
