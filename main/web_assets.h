#pragma once

#include <stddef.h>
#include <stdint.h>

/* One gzip-compressed file from web/. path is relative to web/ with forward slashes. */
typedef struct {
    const char *path;
    const uint8_t *start;
    const uint8_t *end;
} web_asset_t;

/* Generated table (see main/CMakeLists.txt). Terminated by an entry with path NULL. */
extern const web_asset_t web_assets[];
extern const size_t web_assets_count;
