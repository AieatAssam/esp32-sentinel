#include "config.h"
#include "esp_err.h"
#include "esp_event.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "fido/fido.h"
#include "http.h"
#include "led.h"
#include "logbuf.h"
#include "net.h"
#include "nvs_flash.h"
#include "recovery.h"
#include "sensing.h"
#include "usb.h"

static const char *TAG = "main";

#if CONFIG_DEV_BACKDOOR
/* Dev only: internal RAM left after each init step, read back with GET /api/log. */
#define MEM(what) ESP_LOGI(TAG, "mem after %s: internal %u, largest %u, dma %u", what,                     \
                           (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL),                          \
                           (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL),                 \
                           (unsigned)heap_caps_get_free_size(MALLOC_CAP_DMA | MALLOC_CAP_INTERNAL))
#else
#define MEM(what) ((void)0)
#endif

/* After recovery_check_on_boot() nothing may abort the boot: log the error and go on,
 * so the device stays reachable over HTTP and the crash-loop guard sees a healthy path. */
#define STEP(call)                                                        \
    do {                                                                  \
        esp_err_t _e = (call);                                            \
        if (_e != ESP_OK) ESP_LOGE(TAG, "%s failed: %s", #call, esp_err_to_name(_e)); \
    } while (0)

void app_main(void)
{
    logbuf_init();
    MEM("start");
    /* Before anything else: a crash loop drops into download mode here. */
    recovery_check_on_boot();

    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_LOGW(TAG, "nvs partition needs erase, erasing nvs only");
        STEP(nvs_flash_erase());
        err = nvs_flash_init();
    }
    STEP(err);

    STEP(config_init());
    MEM("config");
    led_set_mode(LED_BOOT);

    STEP(esp_netif_init());
    STEP(esp_event_loop_create_default());
    MEM("netif/event");
    STEP(net_init());
    MEM("net");
    STEP(usb_init());
    MEM("usb");
    STEP(http_start());
    MEM("http");

    fido_init();
    MEM("fido");
    sensing_start();
    MEM("sensing");
    led_set_mode(LED_PRESENT);
    ESP_LOGI(TAG, "boot complete");
}
