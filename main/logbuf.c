#include "logbuf.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

#define LOGBUF_LINE    256

static char s_ring[LOGBUF_SIZE];
static size_t s_head;     /* next write position */
static size_t s_count;    /* bytes stored, capped at LOGBUF_SIZE */
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

static int ring_vprintf(const char *fmt, va_list ap)
{
    va_list copy;
    va_copy(copy, ap);
    int r = s_console ? s_console(fmt, ap) : 0;   /* original sink first, consumes ap */

    /* Formatted once into the static line under a mutex. From an ISR or a critical section, or when another task holds
     * the line for over 10 ms, the line reaches the console only. */
    if (s_fmt_lock && xPortCanYield() && xSemaphoreTake(s_fmt_lock, pdMS_TO_TICKS(10)) == pdTRUE) {
        int n = vsnprintf(s_line, sizeof(s_line), fmt, copy);
        if (n > 0) ring_put(s_line, (size_t)n < sizeof(s_line) ? (size_t)n : sizeof(s_line) - 1);
        xSemaphoreGive(s_fmt_lock);
    }
    va_end(copy);
    return r;
}

void logbuf_init(void)
{
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
