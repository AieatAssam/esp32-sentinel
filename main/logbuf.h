#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "sdkconfig.h"

#if CONFIG_DEV_BACKDOOR
/* Dev only: internal RAM left at a boot step, read back with GET /api/log. Uses the caller's TAG. */
#define MEM(what) ESP_LOGI(TAG, "mem after %s: internal %u, largest %u, dma %u", what,                     \
                           (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL),                          \
                           (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL),                 \
                           (unsigned)heap_caps_get_free_size(MALLOC_CAP_DMA | MALLOC_CAP_INTERNAL))

/* Dev only: the most recent panic, kept apart from the log ring so it survives rollover (not a
 * power cycle). Filled by the panic capture in logbuf.c. */
typedef struct { uint32_t core, pc, a0, sp, cause, uptime_s; } logbuf_panic_t;
/* Copies the record and returns true when one is stored and intact. */
bool logbuf_last_panic(logbuf_panic_t *out);
#else
#define MEM(what) ((void)0)
#endif

/* 4 KB was too small: the esp_tinyusb descriptor banner plus routine boot lines
 * could push early lines (net, usb) out before anyone read the ring. */
#define LOGBUF_SIZE 65536    /* PSRAM; large enough to keep the lines before a reset */

/* Hooks esp_log so the last LOGBUF_SIZE bytes of log output are kept in RAM. Call first in app_main. */
void logbuf_init(void);
/* Copies the newest output (up to cap bytes, oldest first) into out. Returns bytes copied. */
size_t logbuf_read(char *out, size_t cap);
/* Copies up to cap bytes starting off bytes after the oldest stored byte. Returns bytes copied. */
size_t logbuf_read_at(size_t off, char *out, size_t cap);
