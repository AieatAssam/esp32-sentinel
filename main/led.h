#pragma once

#include <stdbool.h>

typedef enum {
    LED_BOOT,
    LED_PRESENT,
    LED_AWAY,
    LED_LOCKED,
    LED_FIDO_WAIT,
    LED_FIDO_OK,
    LED_ERROR,
} led_mode_t;

/* Sets the status LED mode. The driver task starts on first use and follows
 * config led_gpio / led_brightness on every frame. */
void led_set_mode(led_mode_t m);
/* Last mode set outside the FIDO touch prompt (FIDO_WAIT/FIDO_OK are skipped). */
led_mode_t led_get_mode(void);
/* Latches a fault (sensing could not start). While set, the LED shows LED_ERROR whatever app
 * mode is set later; only the FIDO touch prompt still shows over it. */
void led_set_fault(bool on);
