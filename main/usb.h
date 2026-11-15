#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"

/* Installs TinyUSB with the composite descriptor: CDC-NCM, HID FIDO, HID keyboard.
 * Must run after net_init(). */
esp_err_t usb_init(void);

/* Presses and releases one key on the boot keyboard. Callers are serialised. Returns true only
 * when both the press and the release were queued. Returns false at once when the keyboard is not
 * enumerated or the bus is suspended (no remote wakeup). If the press went out but the release
 * could not (bus suspended in between), the release is sent first on the next call. */
bool usb_keyboard_tap(uint8_t modifiers, uint8_t keycode);

/* Receive callback used by the NCM network interface (defined in net.c). */
esp_err_t net_usb_rx(void *buffer, uint16_t len, void *ctx);
/* Resets the net frame-log counters when the host mounts the device (defined in net.c). */
void net_usb_mounted(void);
