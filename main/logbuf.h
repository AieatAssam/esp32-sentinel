#pragma once

#include <stddef.h>

/* 4 KB was too small: the esp_tinyusb descriptor banner plus routine boot lines
 * could push early lines (net, usb) out before anyone read the ring. */
#define LOGBUF_SIZE 16384

/* Hooks esp_log so the last LOGBUF_SIZE bytes of log output are kept in RAM. Call first in app_main. */
void logbuf_init(void);
/* Copies the newest output (up to cap bytes, oldest first) into out. Returns bytes copied. */
size_t logbuf_read(char *out, size_t cap);
/* Copies up to cap bytes starting off bytes after the oldest stored byte. Returns bytes copied. */
size_t logbuf_read_at(size_t off, char *out, size_t cap);
