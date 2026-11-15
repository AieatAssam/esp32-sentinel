# Third-party notices

S3 Sentinel itself is MIT licensed (see `LICENSE`). It includes or links the
third-party components listed below. License texts for the components shipped in the
repository are in `licenses/`. Components pulled in by the build through the ESP
component registry are fetched at build time into `managed_components/` (not committed),
and carry their own `LICENSE` files there.

## Shipped in the web dashboard (`web/`)

| Component | Where | License | Copy |
|---|---|---|---|
| three.js r170 (`three.module.min.js`) | `web/vendor/` | MIT. The file carries the MIT `@license` block | `licenses/three.js-MIT.txt` |
| three.js example addons (`OrbitControls`, postprocessing passes, shaders) | `web/vendor/addons/` | Taken from the three.js project, which is MIT. The addon files carry no license header of their own | `licenses/three.js-MIT.txt` |
| Host Grotesk (font, `host-grotesk-latin.woff2`) | `web/vendor/fonts/` | SIL Open Font License 1.1. Copyright 2023 The Host Grotesk Project Authors (https://github.com/Element-Type/HostGrotesk) | `licenses/OFL-1.1-HostGrotesk.txt` |
| Atkinson Hyperlegible Mono (font, `atkinson-hyperlegible-mono-latin.woff2`) | `web/vendor/fonts/` | SIL Open Font License 1.1. Copyright 2020-2024 The Atkinson Hyperlegible Mono Project Authors (https://github.com/googlefonts/atkinson-hyperlegible-next-mono) | `licenses/OFL-1.1-AtkinsonHyperlegibleMono.txt` |

The web assets are embedded into the firmware image as gzip data.

## Compiled into the firmware (`main/`, via ESP-IDF and managed components)

Versions for the managed components are from `dependencies.lock`.

| Component | Version | License | Copy |
|---|---|---|---|
| ESP-IDF | v6.0.1 (build target) | Apache-2.0 | `licenses/Apache-2.0.txt` |
| espressif/esp_tinyusb | 2.2.0 | Apache-2.0 | `licenses/Apache-2.0.txt` |
| espressif/led_strip | 3.0.3 | Apache-2.0 | `licenses/Apache-2.0.txt` |
| espressif/tinyusb (TinyUSB) | 0.19.0~3 | MIT | `licenses/tinyusb-MIT.txt` |
| espressif/cbor (TinyCBOR) | 7.1.0 | MIT | `licenses/cbor-tinycbor-MIT.txt` |
| espressif/cjson (cJSON) | 1.7.19~2 | MIT | `licenses/cJSON-MIT.txt` |
| NimBLE (inside ESP-IDF) | per ESP-IDF | Apache-2.0 | `licenses/NimBLE-Apache-2.0.txt` |
| lwIP (inside ESP-IDF) | per ESP-IDF | BSD-3-Clause | `licenses/lwIP-BSD-3-Clause.txt` |
| FreeRTOS (inside ESP-IDF) | per ESP-IDF | MIT | `licenses/FreeRTOS-MIT.txt` |
| Mbed TLS (inside ESP-IDF) | per ESP-IDF | Apache-2.0 OR GPL-2.0-or-later (you may choose) | `licenses/mbedtls-dual-Apache-2.0-or-GPL-2.0.txt` |
| TF-PSA-Crypto (inside ESP-IDF) | per ESP-IDF | Apache-2.0 OR GPL-2.0-or-later (you may choose) | `licenses/tf-psa-crypto-dual-Apache-2.0-or-GPL-2.0.txt` |
| Espressif Wi-Fi, PHY, coexistence, OpenThread and Bluetooth controller binary libraries (inside ESP-IDF) | per ESP-IDF | The `LICENSE` files beside these libraries in the ESP-IDF tree are Apache-2.0 for `esp_wifi/lib`, `esp_phy/lib`, `esp_coex/lib`, `openthread/lib`, and `bt/controller/lib_esp32c3_family`. The Bluetooth controller library used on ESP32-S3 has not been confirmed | Not copied to `licenses/`. See the open items |

The ESP-IDF rows give the version in use. ESP-IDF's own components are not pinned
separately in this repository beyond the ESP-IDF version in `docs/BUILDING.md`.

## Open items

- The Espressif binary libraries are shipped as precompiled blobs in the ESP-IDF tree.
  Their license files are cited above, but the copies are not in `licenses/`. The
  Bluetooth controller path for ESP32-S3 has not been confirmed. Check the ESP-IDF tree
  for the matching `LICENSE` before publishing firmware binaries.
- The three.js example addons under `web/vendor/addons/` carry no per-file license
  header. Their provenance is taken from the three.js project. Confirm the source
  version before publishing.
- The license texts in `licenses/` are the standard texts. Compare them with the
  upstream copies at the pinned versions before release.
