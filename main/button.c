#include "button.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "driver/gpio.h"

#define BOOT_GPIO GPIO_NUM_0
#define DEBOUNCE_SAMPLES 3   /* 3 x 10 ms = 30 ms stable low */

static bool s_inited = false;

static void button_init(void)
{
    gpio_config_t cfg = {
        .pin_bit_mask = 1ULL << BOOT_GPIO,
        .mode = GPIO_MODE_INPUT,
        .pull_up_en = GPIO_PULLUP_ENABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE,
    };
    gpio_config(&cfg);
    s_inited = true;
}

bool button_wait_press(uint32_t timeout_ms)
{
    return button_wait_hold(timeout_ms, DEBOUNCE_SAMPLES * 10);
}

bool button_wait_hold(uint32_t timeout_ms, uint32_t hold_ms)
{
    if (!s_inited) button_init();
    int need = (int)(hold_ms / 10) > 0 ? (int)(hold_ms / 10) : 1;

    TickType_t start = xTaskGetTickCount();
    TickType_t limit = pdMS_TO_TICKS(timeout_ms);
    bool armed = false;       /* seen released since the call started */
    int low_samples = 0;

    for (;;) {
        if (timeout_ms != 0 && (xTaskGetTickCount() - start) >= limit) return false;
        if (gpio_get_level(BOOT_GPIO) == 1) {
            armed = true;
            low_samples = 0;
        } else if (armed) {
            if (++low_samples >= need) return true;
        }
        vTaskDelay(pdMS_TO_TICKS(10));
    }
}
