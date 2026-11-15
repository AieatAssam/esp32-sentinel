#include "lock.h"

#include <string.h>
#include "config.h"
#include "usb.h"

/* HID usage IDs and modifier bits (USB HID Usage Tables). */
#define MOD_LCTRL 0x01
#define MOD_LGUI  0x08
#define KEY_L     0x0F
#define KEY_Q     0x14

bool lock_send(void)
{
    const app_config_t *c = config_get();
    if (strcmp(c->lock_os, "mac") == 0) return usb_keyboard_tap(MOD_LCTRL | MOD_LGUI, KEY_Q);   /* Ctrl+Cmd+Q */
    return usb_keyboard_tap(MOD_LGUI, KEY_L);                                                    /* Win+L / Super+L */
}
