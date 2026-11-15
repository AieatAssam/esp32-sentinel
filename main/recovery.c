#include "recovery.h"

#include "config.h"

#include "esp_attr.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "tusb.h"
#include "soc/rtc_cntl_reg.h"
#include "soc/soc.h"

static const char *TAG = "recovery";

#define BOOT_MAGIC        0x5A17C0DEu
#define ABNORMAL_LIMIT    3
#define HEALTHY_US        (20 * 1000 * 1000)

/* RTC no-init memory survives software resets and panics, not power loss. */
static RTC_NOINIT_ATTR uint32_t s_magic;
static RTC_NOINIT_ATTR uint32_t s_abnormal_count;
static RTC_NOINIT_ATTR uint32_t s_safe;    /* SAFE_MAGIC: safe mode, kept across panics */
#define SAFE_MAGIC 0x5AFE5AFEu

static const char *s_reason = "unknown";

static void healthy_cb(void *arg)
{
    (void)arg;
    s_abnormal_count = 0;
    ESP_LOGI(TAG, "healthy for 20 s, crash counter cleared");
}

static const char *reason_str(esp_reset_reason_t r)
{
    switch (r) {
    case ESP_RST_POWERON:   return "power_on";
    case ESP_RST_SW:        return "software";
    case ESP_RST_PANIC:     return "panic";
    case ESP_RST_INT_WDT:   return "int_wdt";
    case ESP_RST_TASK_WDT:  return "task_wdt";
    case ESP_RST_WDT:       return "wdt";
    case ESP_RST_BROWNOUT:  return "brownout";
    case ESP_RST_DEEPSLEEP: return "deepsleep";
    case ESP_RST_EXT:       return "external";
    case ESP_RST_USB:       return "usb";
    default:                return "other";
    }
}

void recovery_check_on_boot(void)
{
    esp_reset_reason_t r = esp_reset_reason();
    s_reason = reason_str(r);

    /* A download request that the ROM did not consume must not stick: clear it so
     * a normal boot does not land in download mode again. */
    REG_WRITE(RTC_CNTL_OPTION1_REG, REG_READ(RTC_CNTL_OPTION1_REG) & ~RTC_CNTL_FORCE_DOWNLOAD_BOOT);

    if (s_magic != BOOT_MAGIC) {
        s_magic = BOOT_MAGIC;
        s_abnormal_count = 0;
        s_safe = 0;
    }
    if (r == ESP_RST_SW) s_safe = 0;   /* a requested reboot leaves safe mode */

    bool abnormal = (r == ESP_RST_PANIC || r == ESP_RST_INT_WDT || r == ESP_RST_TASK_WDT ||
                     r == ESP_RST_WDT || r == ESP_RST_BROWNOUT);
    if (abnormal) {
        s_abnormal_count++;
    } else {
        s_abnormal_count = 0;
    }
    ESP_LOGI(TAG, "boot reason %s, consecutive abnormal resets %lu", s_reason,
             (unsigned long)s_abnormal_count);

    if (s_abnormal_count >= ABNORMAL_LIMIT) {
        s_abnormal_count = 0;
#if !CONFIG_DEV_BACKDOOR
        if (s_safe != SAFE_MAGIC) {
            /* Release: stay reachable (dashboard, FIDO) with the radio off rather than leave the
             * ROM download port open to whatever is plugged in. */
            s_safe = SAFE_MAGIC;
            ESP_LOGE(TAG, "crash loop detected, safe mode: sensing off");
        } else
#endif
        {
            ESP_LOGE(TAG, "crash loop detected, entering download mode");
            recovery_reboot(true);
        }
    }
    if (s_safe == SAFE_MAGIC) ESP_LOGW(TAG, "safe mode: sensing off until reboot");

    esp_timer_handle_t t;
    esp_timer_create_args_t args = {.callback = healthy_cb, .name = "healthy"};
    if (esp_timer_create(&args, &t) == ESP_OK) {
        esp_timer_start_once(t, HEALTHY_US);
    }
}

void recovery_reboot(bool download_mode)
{
    config_flush();   /* a coalesced config change must not be lost */
    if (download_mode) {
        ESP_LOGW(TAG, "rebooting into ROM download mode");
        /* Drop off the bus first so the host sees a clean detach. */
        if (tud_inited()) {   /* not yet installed on the crash-loop path */
            tud_disconnect();
            vTaskDelay(pdMS_TO_TICKS(100));
        }
        /* TinyUSB routed the internal PHY to USB-OTG via RTC_CNTL_USB_CONF, which is in
         * the RTC domain and survives esp_restart(). Hand the PHY back to hardware
         * control (USB-Serial/JTAG) so the ROM download port can enumerate. */
        REG_CLR_BIT(RTC_CNTL_USB_CONF_REG, RTC_CNTL_SW_HW_USB_PHY_SEL | RTC_CNTL_SW_USB_PHY_SEL);
        REG_WRITE(RTC_CNTL_OPTION1_REG, RTC_CNTL_FORCE_DOWNLOAD_BOOT);
    }
    esp_restart();
}

bool recovery_safe_mode(void)
{
    return s_safe == SAFE_MAGIC;
}

const char *recovery_reset_reason_str(void)
{
    return s_reason;
}
