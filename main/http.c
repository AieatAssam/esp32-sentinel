/* HTTP API and dashboard on the USB link only (192.168.7.1:80).
 *
 * Security model of this server (for SECURITY.md):
 *  - Reachability. The listener is bound to the USB NCM netif with SO_BINDTODEVICE (lwIP drops a
 *    SYN for a netif-bound listen pcb that arrived on another netif, tcp_in.c), and open_fn also
 *    refuses any connection whose local address is not 192.168.7.1 or whose peer is not a host in
 *    192.168.7.0/24. In joined mode a station lease that overlaps 192.168.7.0/24 is refused
 *    (sensing.c). Nothing on the Wi-Fi side can reach this server.
 *  - Browsers. Every request must carry Host 192.168.7.1[:80] (stops DNS rebinding), POSTs need
 *    Origin http://192.168.7.1 and application/json (stops cross-site forms), and every response
 *    carries X-Frame-Options DENY and a CSP with frame-ancestors 'none' (stops clickjacking).
 *  - Local processes. RESIDUAL RISK, stated plainly: any program running on the host the device
 *    is plugged into can send these exact headers, so it has the same power as the dashboard.
 *    There is no secret a local process cannot read: a per-boot token handed to the dashboard
 *    by a GET is equally available to any local process making that GET, and nothing is stored
 *    on the host that the device could verify. A token would therefore be theatre and is not
 *    added. Such a process can: turn auto-lock off, change lock_os so the lock shortcut is
 *    wrong for the host, join or forget a Wi-Fi network, recalibrate, read presence and the
 *    radio scene, and trigger a lock (rate-limited to one per 5 s). The operations that are
 *    dangerous beyond this host's own session need a physical BOOT press on the device: ROM
 *    download mode (release builds: hold BOOT 3 s within 30 s), FIDO reset and FIDO harden. In
 *    release builds /api/log is absent. A process with that much access to the host can, in
 *    general, already act as the logged-in user, so the device does not try to defend the
 *    user's own session against it.
 *  - Dev builds (CONFIG_DEV_BACKDOOR=y) restore immediate download mode and /api/log and are not
 *    for release.
 */
#include "http.h"

#include <errno.h>
#include <math.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "button.h"
#include "cJSON.h"
#include "sdkconfig.h"
#include "config.h"
#include "esp_check.h"
#include "esp_heap_caps.h"
#include "esp_http_server.h"
#include "esp_netif.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "fido/fido.h"
#include "lock.h"
#include "logbuf.h"
#include "lwip/sockets.h"
#include "net_policy.h"
#include "recovery.h"
#include "sensing.h"
#include "web_assets.h"

static const char *TAG = "http";

#define ALLOWED_ORIGIN   "http://192.168.7.1"
#define MAX_WS_CLIENTS   4
#define MAX_BODY         512
#define MAX_WS_IN        128            /* client frames are discarded; larger ones close the session */
#define SNAP_MAX         16384          /* sensing frame bound (typ. 6-8 KB); allocated in PSRAM */
#define WS_PERIOD_US     (100 * 1000)   /* 10 Hz */
#define HTTPD_SESSIONS   10             /* a browser alone holds 6 keep-alive connections plus the WS */
/* lwIP must run out of sockets after httpd's session table, never before: LRU purge only fires on
 * a full session table, and an accept() failing with ENFILE first leaves the server dead for as
 * long as the clients hold their sockets. 3 = httpd internals, 1 = sensing ICMP, 2 spare. */
_Static_assert(CONFIG_LWIP_MAX_SOCKETS >= HTTPD_SESSIONS + 3 + 1 + 2, "lwIP socket budget");
#define FW_VERSION       "0.1.0"
#define LOCK_MIN_US      (5LL * 1000000)  /* POST /api/lock: one per 5 s */
#define WRITE_MIN_US     (5LL * 1000000)  /* calibrate and wifi (NVS writes): one per 5 s each */
#define DL_CONFIRM_MS    30000            /* download mode: BOOT must be held within 30 s ... */
#define DL_HOLD_MS       3000             /* ... for 3 s, so a FIDO touch (a tap) never counts */

#if CONFIG_DEV_BACKDOOR
#define BUILD_DEV_BACKDOOR 1
#else
#define BUILD_DEV_BACKDOOR 0
#endif

/* Security headers on every response. The script hash is of the inline importmap in
 * web/index.html (the exact text between its <script> tags); a change to that block needs a new
 * hash, or the dashboard's module imports fail. To recompute:
 *   python3 -c "import re,hashlib,base64;s=open('web/index.html').read();m=re.search(r'<script type=\"importmap\">(.*?)</script>',s,re.S);print(base64.b64encode(hashlib.sha256(m.group(1).encode()).digest()).decode())" */
#define CSP "default-src 'self'; script-src 'self' 'sha256-p88oqFV+VvqgWHhxGwTi45SAQOmulL1/9gmQyjN/44Q='; style-src 'self'; " \
            "img-src 'self' data:; connect-src 'self' ws://192.168.7.1; object-src 'none'; "      \
            "base-uri 'none'; form-action 'self'; frame-ancestors 'none'"

/* All fd bookkeeping and sends run on the httpd task (handlers, close_fn and queued work),
 * so no locking is needed. */
static httpd_handle_t s_server;
static int s_ws_fds[MAX_WS_CLIENTS];

/* Two PSRAM buffers, both used only from the httpd task. The WS payload must survive until
 * its queued async send runs, and a status request can run in between, so they cannot be shared. */
static char *s_ws_buf;      /* WS frame, built by ws_push_work */
static char *s_st_buf;      /* sensing JSON for /api/status */

/* ---------- Origin and content-type checks ---------- */

/* Returns true when the Origin header is exactly the device origin. */
static bool origin_ok(httpd_req_t *req)
{
    size_t n = httpd_req_get_hdr_value_len(req, "Origin");
    if (n == 0 || n > 64) {
        return false;
    }
    char buf[80];
    if (httpd_req_get_hdr_value_str(req, "Origin", buf, sizeof(buf)) != ESP_OK) {
        return false;
    }
    return strcmp(buf, ALLOWED_ORIGIN) == 0;
}

/* GET requests may come from a non-browser client with no Origin; a present but
 * foreign Origin is always rejected. */
static bool origin_ok_or_absent(httpd_req_t *req)
{
    if (httpd_req_get_hdr_value_len(req, "Origin") == 0) {
        return true;
    }
    return origin_ok(req);
}

static bool is_json_content_type(httpd_req_t *req)
{
    char buf[64];
    if (httpd_req_get_hdr_value_str(req, "Content-Type", buf, sizeof(buf)) != ESP_OK) {
        return false;
    }
    return strncmp(buf, "application/json", 16) == 0;
}

/* Checks a POST: Origin must match, Content-Type must be application/json. */
static esp_err_t check_post(httpd_req_t *req)
{
    if (!origin_ok(req)) {
        httpd_resp_send_err(req, HTTPD_403_FORBIDDEN, "bad origin");
        return ESP_FAIL;
    }
    if (!is_json_content_type(req)) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "application/json required");
        return ESP_FAIL;
    }
    return ESP_OK;
}

/* Reads the request body into buf (NUL-terminated). Returns ESP_OK or sends an error. */
static esp_err_t read_body(httpd_req_t *req, char *buf, size_t buf_len)
{
    if (req->content_len <= 0 || (size_t)req->content_len >= buf_len) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "empty or oversized body");
        return ESP_FAIL;
    }
    int got = 0;
    while (got < req->content_len) {
        int r = httpd_req_recv(req, buf + got, req->content_len - got);
        if (r <= 0) {
            httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "body read failed");
            return ESP_FAIL;
        }
        got += r;
    }
    buf[got] = '\0';
    return ESP_OK;
}

static esp_err_t send_json(httpd_req_t *req, cJSON *root)
{
    char *s = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!s) {
        return httpd_resp_send_500(req);
    }
    httpd_resp_set_type(req, "application/json");
    esp_err_t err = httpd_resp_sendstr(req, s);
    free(s);
    return err;
}

/* ---------- /api/config ---------- */

static esp_err_t config_get_handler(httpd_req_t *req)
{
    if (!origin_ok_or_absent(req)) {
        return httpd_resp_send_err(req, HTTPD_403_FORBIDDEN, "bad origin");
    }
    const app_config_t *c = config_get();
    cJSON *root = cJSON_CreateObject();
    cJSON_AddBoolToObject(root, "autolock", c->autolock);
    cJSON_AddNumberToObject(root, "away_secs", c->away_secs);
    cJSON_AddNumberToObject(root, "motion_threshold", c->motion_threshold);
    cJSON_AddStringToObject(root, "lock_os", c->lock_os);
    cJSON_AddNumberToObject(root, "led_gpio", c->led_gpio);
    cJSON_AddNumberToObject(root, "led_brightness", c->led_brightness);
    cJSON_AddNumberToObject(root, "channel", c->channel);
    cJSON_AddBoolToObject(root, "use_breathing", c->use_breathing);
    cJSON_AddBoolToObject(root, "use_baseline", c->use_baseline);
    return send_json(req, root);
}

/* Partial merge: only keys present in the body are changed. Type errors and
 * range errors are rejected by config_set(). */
static esp_err_t config_post_handler(httpd_req_t *req)
{
    if (check_post(req) != ESP_OK) {
        return ESP_FAIL;
    }
    char body[MAX_BODY];
    if (read_body(req, body, sizeof(body)) != ESP_OK) {
        return ESP_FAIL;
    }
    cJSON *in = cJSON_Parse(body);
    if (!in || !cJSON_IsObject(in)) {
        cJSON_Delete(in);
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "invalid json object");
    }

    app_config_t c = *config_get();
    const cJSON *j;
    bool bad_type = false;

    if ((j = cJSON_GetObjectItem(in, "autolock"))) {
        if (cJSON_IsBool(j)) c.autolock = cJSON_IsTrue(j); else bad_type = true;
    }
    if ((j = cJSON_GetObjectItem(in, "away_secs"))) {
        if (cJSON_IsNumber(j)) c.away_secs = (int)j->valuedouble; else bad_type = true;
    }
    if ((j = cJSON_GetObjectItem(in, "motion_threshold"))) {
        if (cJSON_IsNumber(j)) c.motion_threshold = (float)j->valuedouble; else bad_type = true;
    }
    if ((j = cJSON_GetObjectItem(in, "lock_os"))) {
        if (cJSON_IsString(j) && strlen(j->valuestring) < sizeof(c.lock_os)) {
            strlcpy(c.lock_os, j->valuestring, sizeof(c.lock_os));
        } else {
            bad_type = true;
        }
    }
    if ((j = cJSON_GetObjectItem(in, "led_gpio"))) {
        if (cJSON_IsNumber(j)) c.led_gpio = (int)j->valuedouble; else bad_type = true;
    }
    if ((j = cJSON_GetObjectItem(in, "led_brightness"))) {
        if (cJSON_IsNumber(j)) c.led_brightness = (int)j->valuedouble; else bad_type = true;
    }
    if ((j = cJSON_GetObjectItem(in, "channel"))) {
        if (cJSON_IsNumber(j)) c.channel = (int)j->valuedouble; else bad_type = true;
    }
    if ((j = cJSON_GetObjectItem(in, "use_breathing"))) {
        if (cJSON_IsBool(j)) c.use_breathing = cJSON_IsTrue(j); else bad_type = true;
    }
    if ((j = cJSON_GetObjectItem(in, "use_baseline"))) {
        if (cJSON_IsBool(j)) c.use_baseline = cJSON_IsTrue(j); else bad_type = true;
    }
    cJSON_Delete(in);

    if (bad_type) {
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "wrong field type");
    }
    if (config_set(&c) != ESP_OK) {
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "value out of range");
    }
    return config_get_handler(req);
}

/* ---------- /api/status, /api/lock, /api/reboot ---------- */

/* Undefined Kconfig symbols are absent from sdkconfig.h, so map them to 0 explicitly. */
#if CONFIG_FIDO_TEST_AUTO_UP
#define BUILD_TEST 1
#else
#define BUILD_TEST 0
#endif
#if CONFIG_EFUSE_VIRTUAL
#define BUILD_EFUSE_VIRTUAL 1
#else
#define BUILD_EFUSE_VIRTUAL 0
#endif

#if CONFIG_DEV_AUTORECOVER
#define BUILD_DEV_AUTORECOVER 1
#else
#define BUILD_DEV_AUTORECOVER 0
#endif

/* Set by every registered handler (through served_trampoline), read by the autorecover timer. */
static volatile bool s_served;

static esp_err_t ws_handler(httpd_req_t *req);

/* Host allowlist (M1): a DNS name rebound to 192.168.7.1 is refused. */
static bool host_ok(httpd_req_t *req)
{
    char h[24];
    return httpd_req_get_hdr_value_str(req, "Host", h, sizeof(h)) == ESP_OK && net_policy_host_ok(h);
}

/* Header values must outlive the response: string literals only. */
static void security_headers(httpd_req_t *req)
{
    httpd_resp_set_hdr(req, "X-Frame-Options", "DENY");
    httpd_resp_set_hdr(req, "Content-Security-Policy", CSP);
    httpd_resp_set_hdr(req, "X-Content-Type-Options", "nosniff");
    httpd_resp_set_hdr(req, "Referrer-Policy", "no-referrer");
    if (strncmp(req->uri, "/api/", 5) == 0) httpd_resp_set_hdr(req, "Cache-Control", "no-store");
}

static esp_err_t served_trampoline(httpd_req_t *req)
{
    s_served = true;
    esp_err_t (*h)(httpd_req_t *) = (esp_err_t (*)(httpd_req_t *))req->user_ctx;
    if (h == ws_handler) return h(req);   /* frames on an accepted socket; handshake checked in ws_pre_handshake */
    security_headers(req);
    if (!host_ok(req)) {
        httpd_resp_send_err(req, HTTPD_403_FORBIDDEN, "bad host");
        return ESP_FAIL;                  /* close the connection */
    }
    return h(req);
}

/* httpd task only, so no lock. True when at least min_us passed since the last accepted call. */
static bool rate_ok(int64_t *last_us, int64_t min_us)
{
    int64_t now = esp_timer_get_time();
    if (*last_us && now - *last_us < min_us) return false;
    *last_us = now;
    return true;
}

static esp_err_t too_many(httpd_req_t *req)
{
    httpd_resp_set_status(req, "429 Too Many Requests");
    httpd_resp_set_hdr(req, "Retry-After", "5");
    cJSON *e = cJSON_CreateObject();
    cJSON_AddStringToObject(e, "error", "too many requests, try again in a few seconds");
    return send_json(req, e);
}

#if CONFIG_DEV_AUTORECOVER
static void autorecover_cb(void *arg)
{
    (void)arg;
    if (s_served) {
        ESP_LOGI(TAG, "dev autorecover: HTTP seen, staying up");
        return;
    }
    ESP_LOGE(TAG, "dev autorecover: no HTTP request in 60 s, rebooting into download mode");
    recovery_reboot(true);
}
#endif

static const char *dl_state_str(void);

static esp_err_t status_handler(httpd_req_t *req)
{
    if (!origin_ok_or_absent(req)) {
        return httpd_resp_send_err(req, HTTPD_403_FORBIDDEN, "bad origin");
    }
    size_t n = sensing_snapshot_json(s_st_buf, SNAP_MAX);
    if (n == 0) {
        return httpd_resp_send_500(req);
    }
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "fw", FW_VERSION);
    cJSON_AddNumberToObject(root, "uptime_s", (double)(esp_timer_get_time() / 1000000));
    cJSON_AddNumberToObject(root, "heap", (double)esp_get_free_heap_size());
    cJSON_AddNumberToObject(root, "heap_min", (double)esp_get_minimum_free_heap_size());
    cJSON_AddNumberToObject(root, "psram", (double)heap_caps_get_free_size(MALLOC_CAP_SPIRAM));
    cJSON_AddNumberToObject(root, "heap_free", (double)esp_get_free_heap_size());
    /* "heap" is mostly PSRAM; Wi-Fi, lwIP, NimBLE and the SHA/AES drivers live on internal RAM. */
    cJSON_AddNumberToObject(root, "int_free", (double)heap_caps_get_free_size(MALLOC_CAP_INTERNAL));
    cJSON_AddNumberToObject(root, "int_min", (double)heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL));
    cJSON_AddNumberToObject(root, "int_largest", (double)heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL));
    cJSON_AddNumberToObject(root, "dma_free", (double)heap_caps_get_free_size(MALLOC_CAP_DMA | MALLOC_CAP_INTERNAL));
#if CONFIG_DEV_BACKDOOR
    /* Dev only: unused stack bytes per task (high-water mark), for sizing stacks. */
    static const char *const k_tasks[] = {"main", "sensing", "ping", "led", "fido", "httpd", "TinyUSB",
                                          "nimble_host", "wifi", "tiT", "sys_evt", "esp_timer", "ipc0", "ipc1"};
    cJSON *st = cJSON_AddObjectToObject(root, "dev_stack_free");
    for (size_t i = 0; i < sizeof(k_tasks) / sizeof(k_tasks[0]); i++) {
        TaskHandle_t th = xTaskGetHandle(k_tasks[i]);
        if (th) cJSON_AddNumberToObject(st, k_tasks[i], (double)uxTaskGetStackHighWaterMark(th));
    }
#endif
    cJSON_AddStringToObject(root, "reset_reason", recovery_reset_reason_str());
    cJSON_AddStringToObject(root, "fido", fido_state_str());
    sensing_link_t lk;
    sensing_link_get(&lk);
    cJSON *lj = cJSON_CreateObject();
    cJSON_AddStringToObject(lj, "mode", lk.mode);
    cJSON_AddStringToObject(lj, "state", lk.state);
    if (lk.has_ssid) cJSON_AddStringToObject(lj, "ssid", lk.ssid);
    else cJSON_AddNullToObject(lj, "ssid");
    cJSON_AddItemToObject(root, "link", lj);
    cJSON_AddStringToObject(root, "ip", "192.168.7.1");
    float tc = sensing_temp_get();
    if (isfinite(tc)) cJSON_AddNumberToObject(root, "temp", (double)lroundf(tc * 10.0f) / 10.0);
    else cJSON_AddNullToObject(root, "temp");
    cJSON_AddBoolToObject(root, "test_build", BUILD_TEST);
    cJSON_AddBoolToObject(root, "efuse_virtual", BUILD_EFUSE_VIRTUAL);
    cJSON_AddBoolToObject(root, "dev_autorecover", BUILD_DEV_AUTORECOVER);
    cJSON_AddBoolToObject(root, "dev_build", BUILD_DEV_BACKDOOR);
    cJSON_AddBoolToObject(root, "safe_mode", recovery_safe_mode());
    const char *dl = dl_state_str();
    if (dl) cJSON_AddStringToObject(root, "download", dl);
    else cJSON_AddNullToObject(root, "download");
    cJSON_AddRawToObject(root, "sensing", s_st_buf);
    return send_json(req, root);
}

/* POST /api/calibrate starts a ~10 s empty-room baseline capture; ?clear=1 forgets it. */
static esp_err_t calibrate_handler(httpd_req_t *req)
{
    static int64_t last;
    if (check_post(req) != ESP_OK) {
        return ESP_FAIL;
    }
    if (!rate_ok(&last, WRITE_MIN_US)) return too_many(req);
    char query[32] = {0};
    char val[4] = {0};
    bool clear = httpd_req_get_url_query_str(req, query, sizeof(query)) == ESP_OK &&
                 httpd_query_key_value(query, "clear", val, sizeof(val)) == ESP_OK &&
                 strcmp(val, "1") == 0;
    cJSON *root = cJSON_CreateObject();
    if (clear) {
        sensing_calibrate_clear();
        cJSON_AddStringToObject(root, "baseline", "cleared");
    } else {
        sensing_calibrate_start();
        cJSON_AddStringToObject(root, "baseline", "capturing");
        cJSON_AddNumberToObject(root, "seconds", 10);
    }
    cJSON_AddBoolToObject(root, "ok", true);
    return send_json(req, root);
}

static esp_err_t lock_handler(httpd_req_t *req)
{
    static int64_t last;
    if (check_post(req) != ESP_OK) {
        return ESP_FAIL;
    }
    if (!rate_ok(&last, LOCK_MIN_US)) return too_many(req);
    bool ok = lock_send();
    cJSON *root = cJSON_CreateObject();
    cJSON_AddBoolToObject(root, "ok", ok);
    if (!ok) cJSON_AddStringToObject(root, "error", "keyboard not ready (host asleep or not enumerated)");
    return send_json(req, root);
}

/* Reboot after the response has been flushed. */
static void reboot_timer_cb(void *arg)
{
    recovery_reboot((bool)(intptr_t)arg);
}

/* Release builds: ROM download mode needs BOOT held for DL_HOLD_MS within DL_CONFIRM_MS (H2a).
 * The press is a hold, not a tap, and neither wait may run alongside a FIDO prompt or admin op,
 * so a press meant for one can never confirm the other. State read from GET /api/status
 * "download": null, "waiting_touch", "ok" (rebooting), "timeout", "denied". */
typedef enum { DL_NONE, DL_WAITING, DL_OK, DL_TIMEOUT, DL_DENIED } dl_state_t;
static volatile dl_state_t s_dl = DL_NONE;
static bool fido_op_busy(void);

static const char *dl_state_str(void)
{
    static const char *const n[] = {NULL, "waiting_touch", "ok", "timeout", "denied"};
    return n[s_dl];
}

#if !CONFIG_DEV_BACKDOOR
/* BOOT is claimed (fido_button_claim) by reboot_handler before this task starts. It is released
 * right after the wait, on every outcome, so no path leaves the button claimed. */
static void dl_task(void *arg)
{
    (void)arg;
    bool held = button_wait_hold(DL_CONFIRM_MS, DL_HOLD_MS);
    bool clash = strcmp(fido_state_str(), "idle") != 0 || fido_op_busy();
    fido_button_release();
    s_dl = !held ? DL_TIMEOUT : clash ? DL_DENIED : DL_OK;
    ESP_LOGW(TAG, "download mode %s", dl_state_str());
    if (s_dl == DL_OK) {
        vTaskDelay(pdMS_TO_TICKS(1500));   /* let the dashboard poll see "ok" */
        recovery_reboot(true);
    }
    vTaskDelete(NULL);
}
#endif

static esp_err_t reboot_handler(httpd_req_t *req)
{
    if (check_post(req) != ESP_OK) {
        return ESP_FAIL;
    }
    char query[32] = {0};
    char mode[16] = {0};
    if (httpd_req_get_url_query_str(req, query, sizeof(query)) != ESP_OK ||
        httpd_query_key_value(query, "mode", mode, sizeof(mode)) != ESP_OK) {
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "mode=normal|download required");
    }
    bool download;
    if (strcmp(mode, "download") == 0) {
        download = true;
    } else if (strcmp(mode, "normal") == 0) {
        download = false;
    } else {
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "mode=normal|download required");
    }

#if !CONFIG_DEV_BACKDOOR
    if (download) {
        /* fido_button_claim refuses while a FIDO prompt, command or admin op holds BOOT. */
        if (s_dl == DL_WAITING || fido_op_busy() || strcmp(fido_state_str(), "idle") != 0 ||
            !fido_button_claim()) {
            cJSON *e = cJSON_CreateObject();
            cJSON_AddStringToObject(e, "error", "another BOOT confirmation is pending");
            httpd_resp_set_status(req, "409 Conflict");
            return send_json(req, e);
        }
        s_dl = DL_WAITING;
        if (xTaskCreate(dl_task, "dl_confirm", 3072, NULL, 5, NULL) != pdPASS) {
            fido_button_release();
            s_dl = DL_NONE;
            return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "could not start task");
        }
        httpd_resp_set_status(req, "202 Accepted");
        cJSON *a = cJSON_CreateObject();
        cJSON_AddBoolToObject(a, "accepted", true);
        cJSON_AddStringToObject(a, "confirm", "hold BOOT for 3 s");
        return send_json(req, a);
    }
#endif
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "rebooting", mode);
    esp_err_t err = send_json(req, root);

    esp_timer_handle_t t;
    esp_timer_create_args_t args = {
        .callback = reboot_timer_cb,
        .arg = (void *)(intptr_t)download,
        .name = "reboot",
    };
    if (esp_timer_create(&args, &t) == ESP_OK) {
        esp_timer_start_once(t, 300 * 1000);
    }
    return err;
}

/* ---------- /ws ---------- */

/* s_ws_fds is oldest first, -1 padded at the end. When full, the oldest client is closed so a
 * new dashboard tab always gets frames (L3). */
static void ws_remove(int fd)
{
    int j = 0;
    for (int i = 0; i < MAX_WS_CLIENTS; i++) {
        if (s_ws_fds[i] != fd) s_ws_fds[j++] = s_ws_fds[i];
    }
    while (j < MAX_WS_CLIENTS) s_ws_fds[j++] = -1;
}

/* Sends on a WS session never block: a backgrounded tab stops reading, and a blocking send would
 * hold the single httpd task (SO_SNDTIMEO is enforced from lwIP's 1 s netconn poll, so even a short
 * timeout costs up to 1 s per stuck client per frame). A frame that does not fit in the socket's send
 * buffer at once fails, and so does a short send, which httpd_ws_send_frame_async would otherwise
 * count as success and desync the stream; ws_push_work then closes the session. */
static int ws_send(httpd_handle_t hd, int fd, const char *buf, size_t len, int flags)
{
    (void)hd;
    int r = send(fd, buf, len, flags | MSG_DONTWAIT);
    if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return HTTPD_SOCK_ERR_TIMEOUT;
    return r == (int)len ? r : HTTPD_SOCK_ERR_FAIL;
}

/* Reset rather than FIN: with its send queue full, a graceful close blocks the httpd task for the
 * 2 s send timeout waiting for room to queue the FIN. */
static void ws_drop(int fd)
{
    ws_remove(fd);
    struct linger lg = {.l_onoff = 1, .l_linger = 0};
    setsockopt(fd, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));
    httpd_sess_trigger_close(s_server, fd);
}

static void ws_add(int fd)
{
    for (int i = 0; i < MAX_WS_CLIENTS; i++) {
        if (s_ws_fds[i] == fd) return;
    }
    httpd_sess_set_send_override(s_server, fd, ws_send);
    if (s_ws_fds[MAX_WS_CLIENTS - 1] != -1) {
        ws_drop(s_ws_fds[0]);
    }
    for (int i = 0; i < MAX_WS_CLIENTS; i++) {
        if (s_ws_fds[i] == -1) {
            s_ws_fds[i] = fd;
            return;
        }
    }
}

/* Called by httpd when a session ends. httpd does not close the socket when a
 * custom close_fn is set, so close it here. */
static void session_close_cb(httpd_handle_t hd, int sockfd)
{
    (void)hd;
    ws_remove(sockfd);
    close(sockfd);
}

/* Runs before the WebSocket handshake response is sent. httpd does not call the handler
 * for the handshake itself (no ws_post_handshake_cb in this build), so the client is
 * registered here. A client whose handshake fails is dropped by ws_push_work. */
static esp_err_t ws_pre_handshake(httpd_req_t *req)
{
    if (!host_ok(req) || !origin_ok(req)) {
        httpd_resp_send_err(req, HTTPD_403_FORBIDDEN, "bad origin");
        return ESP_FAIL;
    }
    ws_add(httpd_req_to_sockfd(req));
    return ESP_OK;
}

static esp_err_t ws_handler(httpd_req_t *req)
{
    if (req->method == HTTP_GET) {
        return ESP_OK;
    }
    /* Client frames are discarded. The payload must be read so it is not parsed as the next
     * frame header. Oversized frames close the session. */
    httpd_ws_frame_t f = {.type = HTTPD_WS_TYPE_TEXT};
    if (httpd_ws_recv_frame(req, &f, 0) != ESP_OK) {
        return ESP_FAIL;
    }
    if (f.len > MAX_WS_IN) {
        return ESP_FAIL;
    }
    uint8_t in[MAX_WS_IN + 1];
    if (f.len > 0) {
        f.payload = in;
        if (httpd_ws_recv_frame(req, &f, f.len) != ESP_OK) {
            return ESP_FAIL;
        }
    }
    if (f.type == HTTPD_WS_TYPE_CLOSE) {
        ws_remove(httpd_req_to_sockfd(req));
    }
    return ESP_OK;
}

/* Runs on the httpd task. The timer only queues this, so sends never run on the timer stack
 * and never race with close_fn. */
static atomic_bool s_push_queued;      /* at most one push in the work queue */

static void ws_push_work(void *arg)
{
    (void)arg;
    atomic_store(&s_push_queued, false);
    if (!s_server) return;
    size_t n = sensing_snapshot_json(s_ws_buf, SNAP_MAX);
    if (n == 0) {
        ESP_LOGW(TAG, "sensing frame not built, dropped");
        return;
    }
    httpd_ws_frame_t frame = {
        .type = HTTPD_WS_TYPE_TEXT,
        .payload = (uint8_t *)s_ws_buf,
        .len = n,
    };
    int fds[MAX_WS_CLIENTS];
    memcpy(fds, s_ws_fds, sizeof(fds));      /* ws_remove compacts s_ws_fds */
    for (int i = 0; i < MAX_WS_CLIENTS; i++) {
        int fd = fds[i];
        if (fd == -1) continue;
        if (httpd_ws_get_fd_info(s_server, fd) != HTTPD_WS_CLIENT_WEBSOCKET) {
                ws_remove(fd);
            continue;
        }
        if (httpd_ws_send_frame_async(s_server, fd, &frame) != ESP_OK) {
            /* Slow, dead or desynced: drop it so it neither stalls the next frames nor holds a
             * session slot. The page reconnects if it is still alive. */
            ws_drop(fd);
        } else {
            /* A WS reader never sends, so without this LRU purge would evict it first. */
            httpd_sess_update_lru_counter(s_server, fd);
        }
    }
}

static void ws_push_cb(void *arg)
{
    (void)arg;
    if (s_server && !atomic_exchange(&s_push_queued, true) &&
        httpd_queue_work(s_server, ws_push_work, NULL) != ESP_OK) {
        atomic_store(&s_push_queued, false);
    }
}

/* ---------- static files ---------- */

static const char *mime_for(const char *path)
{
    const char *dot = strrchr(path, '.');
    if (!dot) return "application/octet-stream";
    if (!strcmp(dot, ".html")) return "text/html; charset=utf-8";
    if (!strcmp(dot, ".js") || !strcmp(dot, ".mjs")) return "text/javascript; charset=utf-8";
    if (!strcmp(dot, ".css")) return "text/css; charset=utf-8";
    if (!strcmp(dot, ".json")) return "application/json";
    if (!strcmp(dot, ".svg")) return "image/svg+xml";
    if (!strcmp(dot, ".png")) return "image/png";
    if (!strcmp(dot, ".jpg") || !strcmp(dot, ".jpeg")) return "image/jpeg";
    if (!strcmp(dot, ".ico")) return "image/x-icon";
    if (!strcmp(dot, ".txt")) return "text/plain; charset=utf-8";
    if (!strcmp(dot, ".woff2")) return "font/woff2";
    if (!strcmp(dot, ".woff")) return "font/woff";
    return "application/octet-stream";
}

static esp_err_t static_handler(httpd_req_t *req)
{
    char uri[256];
    strlcpy(uri, req->uri, sizeof(uri));
    char *q = strchr(uri, '?');
    if (q) *q = '\0';

    const char *rel = (strcmp(uri, "/") == 0) ? "index.html" : uri + 1;
    for (size_t i = 0; i < web_assets_count && web_assets[i].path; i++) {
        if (strcmp(web_assets[i].path, rel) == 0) {
            httpd_resp_set_type(req, mime_for(rel));
            httpd_resp_set_hdr(req, "Content-Encoding", "gzip");
            httpd_resp_set_hdr(req, "Cache-Control", "no-cache");
            return httpd_resp_send(req, (const char *)web_assets[i].start,
                                   web_assets[i].end - web_assets[i].start);
        }
    }
    return httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "not found");
}

/* ---------- /api/log ---------- */

#if CONFIG_DEV_BACKDOOR
/* Dev builds only (H2b): last LOGBUF_SIZE bytes of log output, plain text, oldest first. */
static esp_err_t log_get_handler(httpd_req_t *req)
{
    if (!origin_ok_or_absent(req)) {
        return httpd_resp_send_err(req, HTTPD_403_FORBIDDEN, "bad origin");
    }
    size_t cap = LOGBUF_SIZE;
    char *buf = malloc(cap);
    if (!buf) {
        return httpd_resp_send_500(req);
    }
    size_t n = logbuf_read(buf, cap);
    httpd_resp_set_type(req, "text/plain");
    esp_err_t err = httpd_resp_send(req, buf, n);
    free(buf);
    return err;
}

/* Raw CSI drain for tools/csi_capture.py: a uint32 count of records lost to a full ring, then
 * sensing_raw_t records. The first request starts the capture. */
static esp_err_t csi_raw_handler(httpd_req_t *req)
{
    if (!origin_ok_or_absent(req)) {
        return httpd_resp_send_err(req, HTTPD_403_FORBIDDEN, "bad origin");
    }
    /* PSRAM, httpd task only: 5 KB of internal .bss left Wi-Fi unable to allocate frames to join. */
    static sensing_raw_t *rec;
    if (!rec && !(rec = heap_caps_malloc(32 * sizeof(*rec), MALLOC_CAP_SPIRAM))) {
        return httpd_resp_send_500(req);
    }
    uint32_t dropped, d;
    size_t n = sensing_raw_read(rec, 32, &dropped);
    httpd_resp_set_type(req, "application/octet-stream");
    esp_err_t err = httpd_resp_send_chunk(req, (const char *)&dropped, sizeof(dropped));
    for (int i = 0; err == ESP_OK && n > 0 && i < 128; i++) {   /* at most 4096 records per request */
        err = httpd_resp_send_chunk(req, (const char *)rec, n * sizeof(*rec));
        n = sensing_raw_read(rec, 32, &d);
    }
    /* ponytail: drops counted during this request (d) are reported as 0 lost; fine at 0.5 s polling. */
    return err == ESP_OK ? httpd_resp_send_chunk(req, NULL, 0) : err;
}
#endif

/* ---------- start ---------- */

/* ---------- /api/fido ---------- */

/* FIDO admin ops (reset, harden) wait up to 30 s for a BOOT press. They run in their own
 * task so the httpd task and the WebSocket push keep running. GET /api/fido reports the
 * last op and its state. */
typedef enum { FIDO_OP_NONE, FIDO_OP_RESET, FIDO_OP_HARDEN } fido_op_t;
static portMUX_TYPE s_op_mux = portMUX_INITIALIZER_UNLOCKED;
static fido_op_t s_op = FIDO_OP_NONE;   /* guarded by s_op_mux */
static bool s_op_running;               /* guarded by s_op_mux */
static esp_err_t s_op_result;           /* guarded by s_op_mux */

static const char *fido_op_name(fido_op_t op)
{
    return op == FIDO_OP_RESET ? "reset" : op == FIDO_OP_HARDEN ? "harden" : NULL;
}

/* "waiting_touch" while running, then "ok", "timeout" (no BOOT press) or "denied". */
static const char *fido_op_state(fido_op_t *op_out)
{
    portENTER_CRITICAL(&s_op_mux);
    fido_op_t op = s_op;
    bool running = s_op_running;
    esp_err_t err = s_op_result;
    portEXIT_CRITICAL(&s_op_mux);
    *op_out = op;
    if (op == FIDO_OP_NONE) return NULL;
    if (running) return "waiting_touch";
    if (err == ESP_OK) return "ok";
    if (err == ESP_ERR_TIMEOUT) return "timeout";
    return "denied";
}

static void fido_op_task(void *arg)
{
    fido_op_t op = (fido_op_t)(uintptr_t)arg;
    esp_err_t err = op == FIDO_OP_RESET ? fido_admin_reset() : fido_admin_harden();
    portENTER_CRITICAL(&s_op_mux);
    s_op_result = err;
    s_op_running = false;
    portEXIT_CRITICAL(&s_op_mux);
    ESP_LOGI(TAG, "fido %s finished: %s", fido_op_name(op), esp_err_to_name(err));
    vTaskDelete(NULL);
}

__attribute__((unused)) static bool fido_op_busy(void)
{
    portENTER_CRITICAL(&s_op_mux);
    bool busy = s_op_running;
    portEXIT_CRITICAL(&s_op_mux);
    return busy;
}

/* Returns 202 at once. The result is read from GET /api/fido. */
static esp_err_t fido_op_start(httpd_req_t *req, fido_op_t op)
{
    portENTER_CRITICAL(&s_op_mux);
    bool busy = s_op_running || s_dl == DL_WAITING;
    if (!busy) {
        s_op_running = true;
        s_op = op;
    }
    portEXIT_CRITICAL(&s_op_mux);
    if (busy) {
        cJSON *e = cJSON_CreateObject();
        cJSON_AddStringToObject(e, "error", "fido op already running");
        httpd_resp_set_status(req, "409 Conflict");
        return send_json(req, e);
    }
    if (xTaskCreate(fido_op_task, "fido_op", 6144, (void *)(uintptr_t)op, 5, NULL) != pdPASS) {
        portENTER_CRITICAL(&s_op_mux);
        s_op_running = false;
        s_op_result = ESP_ERR_NO_MEM;
        portEXIT_CRITICAL(&s_op_mux);
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "could not start task");
    }
    httpd_resp_set_status(req, "202 Accepted");
    cJSON *root = cJSON_CreateObject();
    cJSON_AddBoolToObject(root, "accepted", true);
    cJSON_AddStringToObject(root, "op", fido_op_name(op));
    return send_json(req, root);
}

static esp_err_t fido_reset_handler(httpd_req_t *req)
{
    if (check_post(req) != ESP_OK) {
        return ESP_FAIL;
    }
    return fido_op_start(req, FIDO_OP_RESET);
}

static esp_err_t fido_harden_handler(httpd_req_t *req)
{
    if (check_post(req) != ESP_OK) {
        return ESP_FAIL;
    }
    char body[64];
    if (read_body(req, body, sizeof(body)) != ESP_OK) {
        return ESP_FAIL;
    }
    /* Exactly {"confirm":"BURN"} and nothing else. */
    bool ok = false;
    cJSON *j = cJSON_Parse(body);
    if (j) {
        cJSON *c = cJSON_GetObjectItemCaseSensitive(j, "confirm");
        ok = cJSON_IsString(c) && strcmp(c->valuestring, "BURN") == 0 && cJSON_GetArraySize(j) == 1;
        cJSON_Delete(j);
    }
    if (!ok) {
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "confirm BURN required");
    }
    return fido_op_start(req, FIDO_OP_HARDEN);
}

static esp_err_t fido_get_handler(httpd_req_t *req)
{
    if (!origin_ok_or_absent(req)) {
        return httpd_resp_send_err(req, HTTPD_403_FORBIDDEN, "bad origin");
    }
    uint32_t n = fido_credential_count();
    cJSON *root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "credentials", n);
    cJSON_AddNumberToObject(root, "count", n);
    cJSON_AddBoolToObject(root, "hardened", fido_is_hardened());
    cJSON_AddBoolToObject(root, "pin_set", fido_pin_is_set());
    cJSON_AddNumberToObject(root, "pin_retries", fido_pin_retries());
    fido_op_t op;
    const char *state = fido_op_state(&op);
    if (state) {
        cJSON_AddStringToObject(root, "op", fido_op_name(op));
        cJSON_AddStringToObject(root, "op_state", state);
    } else {
        cJSON_AddNullToObject(root, "op");
        cJSON_AddNullToObject(root, "op_state");
    }
    return send_json(req, root);
}

/* ---------- /api/wifi (joined mode) ---------- */

static esp_err_t wifi_get_handler(httpd_req_t *req)
{
    if (!origin_ok_or_absent(req)) {
        return httpd_resp_send_err(req, HTTPD_403_FORBIDDEN, "bad origin");
    }
    sensing_link_t l;
    sensing_link_get(&l);
    cJSON *root = cJSON_CreateObject();
    if (l.has_ssid) cJSON_AddStringToObject(root, "ssid", l.ssid);
    else cJSON_AddNullToObject(root, "ssid");
    cJSON_AddStringToObject(root, "state", l.state);
    if (l.has_reason) cJSON_AddStringToObject(root, "reason", l.reason);
    else cJSON_AddNullToObject(root, "reason");
    cJSON_AddNumberToObject(root, "rate", l.rate);
    return send_json(req, root);
}

static esp_err_t wifi_post_handler(httpd_req_t *req)
{
    static int64_t last;
    if (check_post(req) != ESP_OK) {
        return ESP_FAIL;
    }
    if (!rate_ok(&last, WRITE_MIN_US)) return too_many(req);
    char query[32] = {0};
    char val[4] = {0};
    bool clear = httpd_req_get_url_query_str(req, query, sizeof(query)) == ESP_OK &&
                 httpd_query_key_value(query, "clear", val, sizeof(val)) == ESP_OK &&
                 strcmp(val, "1") == 0;
    if (clear) {
        sensing_wifi_forget();
        cJSON *root = cJSON_CreateObject();
        cJSON_AddStringToObject(root, "state", "off");
        cJSON_AddBoolToObject(root, "ok", true);
        return send_json(req, root);
    }

    char body[MAX_BODY];
    if (read_body(req, body, sizeof(body)) != ESP_OK) {
        return ESP_FAIL;
    }
    cJSON *in = cJSON_Parse(body);
    if (!in || !cJSON_IsObject(in)) {
        cJSON_Delete(in);
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "invalid json object");
    }
    const cJSON *ss = cJSON_GetObjectItemCaseSensitive(in, "ssid");
    const cJSON *ps = cJSON_GetObjectItemCaseSensitive(in, "pass");
    if (!cJSON_IsString(ss) || !ss->valuestring || strlen(ss->valuestring) < 1 || strlen(ss->valuestring) > 32) {
        cJSON_Delete(in);
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "ssid must be 1..32 bytes");
    }
    const char *pass = cJSON_IsString(ps) && ps->valuestring ? ps->valuestring : "";
    size_t pl = strlen(pass);
    if (pl > 63 || (pl > 0 && pl < 8)) {
        cJSON_Delete(in);
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "pass must be empty or 8..63 bytes");
    }
    esp_err_t e = sensing_wifi_join(ss->valuestring, pass);   /* copies both strings */
    cJSON_Delete(in);
    if (e != ESP_OK) {
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "wifi not ready");
    }
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "state", "connecting");
    cJSON_AddBoolToObject(root, "ok", true);
    return send_json(req, root);
}

/* Applies a net_policy check to a socket address (IPv4, or IPv6 incl. v4-mapped). */
static bool addr_check(const struct sockaddr_storage *ss, bool (*check)(const uint8_t *, int))
{
    if (ss->ss_family == AF_INET) {
        return check((const uint8_t *)&((const struct sockaddr_in *)ss)->sin_addr.s_addr, 4);
    }
    if (ss->ss_family == AF_INET6) {
        return check(((const struct sockaddr_in6 *)ss)->sin6_addr.s6_addr, 16);
    }
    return false;
}

/* Isolation (H1, second layer behind SO_BINDTODEVICE): an accepted connection must be to
 * 192.168.7.1 and from a host on 192.168.7.0/24. Anything else is refused before a byte is read. */
static esp_err_t open_fn(httpd_handle_t hd, int sockfd)
{
    (void)hd;
    struct sockaddr_storage local, peer;
    socklen_t ll = sizeof(local), pl = sizeof(peer);
    if (getsockname(sockfd, (struct sockaddr *)&local, &ll) != 0 ||
        getpeername(sockfd, (struct sockaddr *)&peer, &pl) != 0) {
        return ESP_FAIL;
    }
    if (!addr_check(&local, net_policy_local_addr_allowed) || !addr_check(&peer, net_policy_peer_allowed)) {
        return ESP_FAIL;
    }
    return ESP_OK;
}

/* H1, first layer: binds httpd's listening socket to the USB NCM netif. lwIP then ignores a SYN
 * that arrived on any other netif (tcp_in.c: listen pcb netif_idx check), whatever its destination
 * address. httpd does not expose its listen fd, so it is found among the lwIP sockets as the one
 * in LISTEN state on port 80. */
static esp_err_t bind_listener_to_usb(void)
{
    esp_netif_t *usb = esp_netif_get_handle_from_ifkey("USB_NCM");
    struct ifreq ifr = {0};
    if (!usb || esp_netif_get_netif_impl_name(usb, ifr.ifr_name) != ESP_OK) return ESP_ERR_NOT_FOUND;
    int bound = 0;
    for (int fd = LWIP_SOCKET_OFFSET; fd < LWIP_SOCKET_OFFSET + CONFIG_LWIP_MAX_SOCKETS; fd++) {
        int listening = 0;
        socklen_t ol = sizeof(listening);
        if (getsockopt(fd, SOL_SOCKET, SO_ACCEPTCONN, &listening, &ol) != 0 || !listening) continue;
        struct sockaddr_storage ss;
        socklen_t sl = sizeof(ss);
        if (getsockname(fd, (struct sockaddr *)&ss, &sl) != 0) continue;
        uint16_t port = ss.ss_family == AF_INET6 ? ((struct sockaddr_in6 *)&ss)->sin6_port
                                                  : ((struct sockaddr_in *)&ss)->sin_port;
        if (ntohs(port) != 80) continue;
        if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr)) == 0) bound++;
    }
    if (!bound) return ESP_FAIL;
    ESP_LOGI(TAG, "listener bound to netif %s", ifr.ifr_name);
    return ESP_OK;
}

esp_err_t http_start(void)
{
    for (int i = 0; i < MAX_WS_CLIENTS; i++) {
        s_ws_fds[i] = -1;
    }

#if CONFIG_DEV_AUTORECOVER
    /* Armed first, so a failure further down still ends in download mode.
     * Measured from boot, not from here: http_start runs a second or so in. */
    esp_timer_handle_t ar;
    esp_timer_create_args_t ar_args = {.callback = autorecover_cb, .name = "autorecover"};
    int64_t left_us = 60LL * 1000 * 1000 - esp_timer_get_time();
    ESP_RETURN_ON_ERROR(esp_timer_create(&ar_args, &ar), TAG, "autorecover timer");
    ESP_RETURN_ON_ERROR(esp_timer_start_once(ar, left_us > 0 ? (uint64_t)left_us : 1), TAG, "autorecover start");
    ESP_LOGW(TAG, "DEV_AUTORECOVER on: download mode at 60 s unless an HTTP request arrives");
#endif

    s_ws_buf = heap_caps_malloc(SNAP_MAX, MALLOC_CAP_SPIRAM);
    s_st_buf = heap_caps_malloc(SNAP_MAX, MALLOC_CAP_SPIRAM);
    if (!s_ws_buf || !s_st_buf) {
        ESP_LOGE(TAG, "psram buffers for sensing frames not allocated");
        return ESP_ERR_NO_MEM;
    }

    httpd_config_t cfg = HTTPD_DEFAULT_CONFIG();
    cfg.uri_match_fn = httpd_uri_match_wildcard;
    cfg.max_uri_handlers = 16;
    cfg.stack_size = 8192;
    cfg.close_fn = session_close_cb;
    cfg.lru_purge_enable = true;
    cfg.max_open_sockets = HTTPD_SESSIONS;
    cfg.backlog_conn = HTTPD_SESSIONS;    /* default 5 dropped the 6th parallel SYN of a page load (1 s retry) */
    cfg.open_fn = open_fn;
    cfg.recv_wait_timeout = 2;            /* L3: a stalled client holds the server for 2 s per recv */
    cfg.send_wait_timeout = 2;

    ESP_RETURN_ON_ERROR(httpd_start(&s_server, &cfg), TAG, "httpd_start");
    if (bind_listener_to_usb() != ESP_OK) {
        /* open_fn still refuses non-USB connections; report it loudly rather than fail the API. */
        ESP_LOGE(TAG, "listener not bound to the USB netif; relying on address checks only");
    }

    const httpd_uri_t uris[] = {
        {.uri = "/api/config", .method = HTTP_GET,  .handler = config_get_handler},
        {.uri = "/api/config", .method = HTTP_POST, .handler = config_post_handler},
        {.uri = "/api/status", .method = HTTP_GET,  .handler = status_handler},
        {.uri = "/api/calibrate", .method = HTTP_POST, .handler = calibrate_handler},
        {.uri = "/api/lock",   .method = HTTP_POST, .handler = lock_handler},
        {.uri = "/api/reboot", .method = HTTP_POST, .handler = reboot_handler},
        {.uri = "/api/fido",   .method = HTTP_GET,  .handler = fido_get_handler},
#if CONFIG_DEV_BACKDOOR
        {.uri = "/api/log",    .method = HTTP_GET,  .handler = log_get_handler},
        {.uri = "/api/csi_raw", .method = HTTP_GET, .handler = csi_raw_handler},
#endif
        {.uri = "/api/fido/reset",   .method = HTTP_POST, .handler = fido_reset_handler},
        {.uri = "/api/fido/harden",  .method = HTTP_POST, .handler = fido_harden_handler},
        {.uri = "/api/wifi",   .method = HTTP_GET,  .handler = wifi_get_handler},
        {.uri = "/api/wifi",   .method = HTTP_POST, .handler = wifi_post_handler},
        {.uri = "/ws",         .method = HTTP_GET,  .handler = ws_handler,
         .is_websocket = true, .handle_ws_control_frames = false,
         .ws_pre_handshake_cb = ws_pre_handshake},
        /* Wildcard last so the API routes above win. */
        {.uri = "/*",          .method = HTTP_GET,  .handler = static_handler},
    };
    for (size_t i = 0; i < sizeof(uris) / sizeof(uris[0]); i++) {
        httpd_uri_t u = uris[i];
        u.user_ctx = (void *)u.handler;   /* no handler uses user_ctx itself */
        u.handler = served_trampoline;
        ESP_RETURN_ON_ERROR(httpd_register_uri_handler(s_server, &u), TAG, "register uri");
    }

    esp_timer_handle_t t;
    esp_timer_create_args_t args = {.callback = ws_push_cb, .name = "ws_push"};
    ESP_RETURN_ON_ERROR(esp_timer_create(&args, &t), TAG, "timer create");
    ESP_RETURN_ON_ERROR(esp_timer_start_periodic(t, WS_PERIOD_US), TAG, "timer start");

    ESP_LOGI(TAG, "http server up on :80");
    return ESP_OK;
}
