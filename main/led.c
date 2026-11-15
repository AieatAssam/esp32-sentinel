#include "led.h"

#include <stdbool.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "led_strip.h"
#include "config.h"
#include "esp_log.h"

static const char *TAG = "led";

static volatile led_mode_t s_mode = LED_BOOT;
static volatile led_mode_t s_app_mode = LED_BOOT;
static volatile bool s_fault;              /* sensing fault: LED_ERROR wins over app modes */
static bool s_task_started = false;
static led_strip_handle_t s_strip = NULL;
static int s_strip_gpio = -1;

static void ensure_strip(int gpio)
{
    if (s_strip && s_strip_gpio == gpio) return;
    if (s_strip) {
        led_strip_del(s_strip);
        s_strip = NULL;
        s_strip_gpio = -1;
    }
    led_strip_config_t sc = {
        .strip_gpio_num = gpio,
        .max_leds = 1,
        .led_model = LED_MODEL_WS2812,
        .color_component_format = LED_STRIP_COLOR_COMPONENT_FMT_GRB,
    };
    led_strip_rmt_config_t rc = {
        .clk_src = RMT_CLK_SRC_DEFAULT,
        .resolution_hz = 10 * 1000 * 1000,
    };
    if (led_strip_new_rmt_device(&sc, &rc, &s_strip) == ESP_OK) {
        s_strip_gpio = gpio;
        ESP_LOGI(TAG, "LED on GPIO%d", gpio);
    } else {
        s_strip = NULL;
        ESP_LOGE(TAG, "LED init failed on GPIO%d", gpio);
    }
}

/* Colour and blink period (ms, 0 = solid) for each mode. */
static void mode_colour(led_mode_t m, uint8_t *r, uint8_t *g, uint8_t *b, int *blink_ms)
{
    *blink_ms = 0;
    switch (m) {
    case LED_BOOT:      *r = 0;   *g = 0;   *b = 255; break;
    case LED_PRESENT:   *r = 0;   *g = 160; *b = 0;   break;
    case LED_AWAY:      *r = 255; *g = 120; *b = 0;   break;
    case LED_LOCKED:    *r = 255; *g = 0;   *b = 0;   break;
    case LED_FIDO_WAIT: *r = 0;   *g = 0;   *b = 255; *blink_ms = 500; break;
    case LED_FIDO_OK:   *r = 255; *g = 255; *b = 255; break;
    case LED_ERROR:     *r = 255; *g = 0;   *b = 0;   *blink_ms = 150; break;
    default:            *r = 0;   *g = 0;   *b = 0;   break;
    }
}

static void led_task(void *arg)
{
    TickType_t t0 = xTaskGetTickCount();
    for (;;) {
        const app_config_t *c = config_get();
        ensure_strip(c->led_gpio);
        if (s_strip) {
            uint8_t r, g, b;
            int blink_ms;
            led_mode_t m = s_mode;
            if (s_fault && m != LED_FIDO_WAIT && m != LED_FIDO_OK) m = LED_ERROR;
            mode_colour(m, &r, &g, &b, &blink_ms);
            bool on = true;
            if (blink_ms > 0) {
                uint32_t ms = (xTaskGetTickCount() - t0) * portTICK_PERIOD_MS;
                on = ((ms / blink_ms) % 2) == 0;
            }
            uint32_t br = (uint32_t)c->led_brightness;
            uint32_t scale = on ? br : 0;
            led_strip_set_pixel(s_strip, 0, r * scale / 255, g * scale / 255, b * scale / 255);
            led_strip_refresh(s_strip);
        }
        vTaskDelay(pdMS_TO_TICKS(50));
    }
}

led_mode_t led_get_mode(void)
{
    return s_app_mode;
}

void led_set_fault(bool on)
{
    s_fault = on;
    if (on) led_set_mode(s_app_mode);   /* starts the task if needed */
}

void led_set_mode(led_mode_t m)
{
    s_mode = m;
    if (m != LED_FIDO_WAIT && m != LED_FIDO_OK) s_app_mode = m;
    if (!s_task_started) {
        s_task_started = true;
        xTaskCreate(led_task, "led", 3072, NULL, 2, NULL);
    }
}
