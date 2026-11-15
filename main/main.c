#include "config.h"
#include "esp_err.h"
#include "esp_event.h"
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
    led_set_mode(LED_BOOT);

    STEP(esp_netif_init());
    STEP(esp_event_loop_create_default());
    STEP(net_init());
    STEP(usb_init());
    STEP(http_start());

    fido_init();
    sensing_start();
    led_set_mode(LED_PRESENT);
    ESP_LOGI(TAG, "boot complete");
}
