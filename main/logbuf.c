#include "esp_attr.h"
#include "esp_cache.h"
#include "logbuf.h"

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

#define LOGBUF_LINE    256

/* PSRAM no-init, written only from task context: the ring survives a panic or watchdog reset (not a
 * power cycle), so GET /api/log after such a reset still shows what led up to it. */
#define LOGBUF_MAGIC 0x4c4f4721u
static EXT_RAM_NOINIT_ATTR struct {
    uint32_t magic;
    size_t head;          /* next write position */
    size_t count;         /* bytes stored, capped at LOGBUF_SIZE */
    char ring[LOGBUF_SIZE];
} s_lb;
#define s_ring  s_lb.ring
#define s_head  s_lb.head
#define s_count s_lb.count
static portMUX_TYPE s_mux = portMUX_INITIALIZER_UNLOCKED;
static vprintf_like_t s_console;
static SemaphoreHandle_t s_fmt_lock;      /* guards s_line: one formatter at a time */
static StaticSemaphore_t s_fmt_lock_buf;
static char s_line[LOGBUF_LINE];           /* static, so the hook costs no stack on small tasks */

static void ring_put(const char *p, size_t n)
{
    portENTER_CRITICAL(&s_mux);
    for (size_t i = 0; i < n; i++) {
        s_ring[s_head] = p[i];
        s_head = (s_head + 1) % LOGBUF_SIZE;
    }
    s_count = (s_count + n > LOGBUF_SIZE) ? LOGBUF_SIZE : s_count + n;
    portEXIT_CRITICAL(&s_mux);
}

/* Write the header and the new bytes back from the data cache to PSRAM. A watchdog or hung-panic reset
 * does not flush the cache, and without this the last lines before it come back as holes of NULs. */
static void ring_sync(size_t from, size_t n)
{
    const int f = ESP_CACHE_MSYNC_FLAG_DIR_C2M | ESP_CACHE_MSYNC_FLAG_UNALIGNED;
    esp_cache_msync(&s_lb, offsetof(typeof(s_lb), ring), f);
    size_t first = n < LOGBUF_SIZE - from ? n : LOGBUF_SIZE - from;
    esp_cache_msync(&s_ring[from], first, f);
    if (n > first) esp_cache_msync(s_ring, n - first, f);
}

static int ring_vprintf(const char *fmt, va_list ap)
{
    va_list copy;
    va_copy(copy, ap);
    int r = s_console ? s_console(fmt, ap) : 0;   /* original sink first, consumes ap */

    /* Formatted once into the static line under a mutex. From an ISR or a critical section, or when another task holds
     * the line for over 10 ms, the line reaches the console only. */
    if (s_fmt_lock && xPortCanYield() && xSemaphoreTake(s_fmt_lock, pdMS_TO_TICKS(10)) == pdTRUE) {
        int n = vsnprintf(s_line, sizeof(s_line), fmt, copy);
        if (n > 0) {
            size_t len = (size_t)n < sizeof(s_line) ? (size_t)n : sizeof(s_line) - 1, from = s_head;
            ring_put(s_line, len);
            ring_sync(from, len);   /* s_head moves only under s_fmt_lock, so from..len is ours */
        }
        xSemaphoreGive(s_fmt_lock);
    }
    va_end(copy);
    return r;
}

void logbuf_init(void)
{
    if (s_lb.magic != LOGBUF_MAGIC || s_head >= LOGBUF_SIZE || s_count > LOGBUF_SIZE) {
        s_lb.magic = LOGBUF_MAGIC;
        s_head = s_count = 0;
    } else {
        size_t from = s_head;
        ring_put("\n--- reset; lines above are from before it ---\n", 47);
        ring_sync(from, 47);
    }
    s_fmt_lock = xSemaphoreCreateMutexStatic(&s_fmt_lock_buf);
    s_console = esp_log_set_vprintf(ring_vprintf);
}

size_t logbuf_read(char *out, size_t cap)
{
    portENTER_CRITICAL(&s_mux);
    size_t n = s_count < cap ? s_count : cap;
    size_t start = (s_head + LOGBUF_SIZE - n) % LOGBUF_SIZE;
    for (size_t i = 0; i < n; i++) {
        out[i] = s_ring[(start + i) % LOGBUF_SIZE];
    }
    portEXIT_CRITICAL(&s_mux);
    return n;
}

size_t logbuf_read_at(size_t off, char *out, size_t cap)
{
    portENTER_CRITICAL(&s_mux);
    size_t avail = off < s_count ? s_count - off : 0;
    size_t n = avail < cap ? avail : cap;
    size_t start = (s_head + LOGBUF_SIZE - s_count + off) % LOGBUF_SIZE;
    for (size_t i = 0; i < n; i++) {
        out[i] = s_ring[(start + i) % LOGBUF_SIZE];
    }
    portEXIT_CRITICAL(&s_mux);
    return n;
}
