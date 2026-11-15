#pragma once

#include "esp_err.h"

/* Starts the HTTP server on port 80 and the 10 Hz WebSocket push timer. Call after net_init(). */
esp_err_t http_start(void);
