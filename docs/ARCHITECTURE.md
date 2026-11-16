# Architecture

S3 Sentinel is firmware for an ESP32-S3 board. To the host it is a USB composite device
with three interfaces: a CDC-NCM network interface, a FIDO HID interface, and a boot
keyboard. It watches the radio environment around it and can lock the host when nobody
is present.

## Components

```
            USB (TinyUSB composite, VID 0x303A, PID 0x4001)
   +-------------------+------------------+-------------------+
   | CDC-NCM network   | HID: CTAPHID     | HID: boot keyboard|
   | 192.168.7.1/24    | (FIDO, main/fido)| (lock shortcut)   |
   +---------+---------+---------+--------+---------+---------+
             |                   |                  |
   HTTP + WebSocket          FIDO handlers      lock.c (keystroke)
   (main/http.c)            (main/fido/*)            ^
             |                                       |
             v                                       |
   Dashboard (web/)     sensing.c  ----> presence --> lock policy
                        threats.c  ----> alerts
                        Wi-Fi CSI, beacon RSSI, NimBLE observer
```

| Area | Files | Role |
|---|---|---|
| Boot and recovery | `main/main.c`, `main/recovery.c`, `main/recovery.h` | Boot order, boot-loop counter, safe mode |
| USB | `main/usb.c`, `main/usb_fido.c`, `main/net.c`, `main/net_policy.h` | Composite descriptors, NCM netif and DHCP, address policy |
| HTTP and WebSocket | `main/http.c` | REST API, WebSocket feed, static dashboard files, Host, Origin and header checks |
| Sensing | `main/sensing.c`, `main/sensing_dsp.c` | Wi-Fi CSI and RSSI processing, presence, motion, breathing, baseline, joined mode |
| Threats | `main/threats.c`, `main/threats.h` | Deauthentication bursts, evil twins and spoofing, BLE tracker kinds |
| Lock | `main/lock.c`, `main/lock.h` | Lock keystroke per host OS, retry policy |
| Config | `main/config.c`, `main/config.h` | Settings in NVS, validation, write coalescing |
| FIDO | `main/fido/` | CTAP2, U2F, CTAPHID, credential store, eFuse hardening |
| Input and LED | `main/button.c`, `main/led.c` | BOOT button with debounce, status LED |
| Logging | `main/logbuf.c` | RAM ring buffer of log lines |
| Dashboard | `web/` | Static HTML, CSS, and JavaScript, compressed and embedded in the firmware |

## Boot sequence

From `app_main()` in `main/main.c`, in order:

1. `logbuf_init`
2. `recovery_check_on_boot` (boot-loop counter; may enter safe mode)
3. NVS initialization
4. `config_init`
5. `net_init` (creates the NCM netif)
6. `usb_init`
7. `http_start`
8. `fido_init`
9. `sensing_start`

Each step after recovery logs its error and continues, so a failing step does not stop
the boot.

## Tasks

| Task | Stack (bytes) | Priority | Created in | Purpose |
|---|---|---|---|---|
| `sensing` | 6144 | 4 | `main/sensing.c` | Sensing tick every 100 ms, presence, lock policy |
| `ping` | 3072 | 3 | `main/sensing.c` | ICMP echo to the joined gateway every 50 ms (joined mode) |
| `led` | 3072 | 2 | `main/led.c` | Status LED patterns |
| `fido` | 16384 | 5 | `main/fido/fido.c` | CTAPHID and CTAP2 request handling |
| `fido_op` | 6144 | 5 | `main/http.c` | One task per admin action (reset, harden), started on request |
| `dl_confirm` | 3072 | 5 | `main/http.c` | Waits for the BOOT hold before download mode, per request (release builds) |
| httpd | 8192 | default | `main/http.c` | `esp_http_server` worker, configured with `stack_size = 8192` |

The stack sizes and priorities come from the `xTaskCreate` and `httpd_config_t` calls.
The TinyUSB task is created by the `esp_tinyusb` component and is not listed.

## Memory

The board has about 340 KB of internal RAM and 8 MB of PSRAM. Internal RAM is kept for what
needs it: Wi-Fi and lwIP buffers (the RX path writes them from the wifi task and must not
land in PSRAM), the NimBLE controller, the SHA/AES driver contexts (DMA-capable), the TinyUSB
NCM buffers (DMA), task stacks that can run with the flash cache disabled (anything writing
NVS: `sensing`, `fido`, httpd), and FIDO secrets (the master key in `store.c`, PIN and
key-agreement state, mbedTLS allocations, which stay internal with
`CONFIG_MBEDTLS_INTERNAL_MEM_ALLOC`).

Everything else large lives in PSRAM:

- Static tables and buffers marked `EXT_RAM_BSS_ATTR` (`CONFIG_SPIRAM_ALLOW_BSS_SEG_EXTERNAL_MEMORY`):
  the sensing AP/BLE/threat/baseline tables, PDP twiddles, breathing buffers, and the CTAPHID request/response/reassembly buffers (wire data only). With the option
  on, IDF also places its own Wi-Fi, WPA and lwIP static tables there.
- The 64 KB log ring, in no-init PSRAM (`EXT_RAM_NOINIT_ATTR`,
  `CONFIG_SPIRAM_ALLOW_NOINIT_SEG_EXTERNAL_MEMORY`). A magic word lets it survive a panic or
  watchdog reset, and each line is written back from the data cache (`esp_cache_msync`) so an
  unclean reset does not drop the last lines; after one, `/api/log` shows the earlier lines, then a "--- reset" marker.
- NimBLE host pools (`CONFIG_BT_NIMBLE_MEM_ALLOC_MODE_EXTERNAL`), the WebSocket and status
  snapshot buffers, the dev raw-CSI ring.

`CONFIG_SPIRAM_TRY_ALLOCATE_WIFI_LWIP` stays off: Wi-Fi and lwIP buffers belong in internal
RAM. Before this split, internal free RAM at steady state (joined, BLE scanning, four
WebSocket clients) was about 7 KB, with a minimum of 23 bytes since boot. `malloc` then fell
back to PSRAM for Wi-Fi RX buffers, and the wifi task crashed copying a frame into one
(CacheError in `wDev_IndicateFrame`). WebSocket handshakes also failed ("Failed to setup
SHA-1"). After the split, steady-state internal free RAM was about 135 KB (see the
CHANGELOG for the measured figures).

`GET /api/status` reports `int_free`, `int_min` (lowest since boot), `int_largest` and
`dma_free`. The dashboard shows `int_free` as "Free internal RAM". `heap` and `heap_free`
include PSRAM. Dev builds also report unused stack per task (`dev_stack_free`) and log the
internal RAM left after each boot step ("mem after ...").

## Build-time embedding

`main/CMakeLists.txt` runs `gzip -9 -n` on every file under `web/` at configure time.
It pulls the compressed files into the app with `.incbin` (`web_assets_data.S`) and
generates `web_assets.c` in the build directory, with its table (`web_assets[]`) and
count. `main/web_assets.h` declares the table for `http.c`. A change to any file under
`web/` requires a firmware rebuild.

## Flash layout

From `partitions.csv`:

| Name | Type | Offset | Size | Use |
|---|---|---|---|---|
| nvs | data | `0x9000` | `0x10000` | Settings, Wi-Fi, FIDO store |
| phy_init | data | `0x19000` | `0x1000` | PHY calibration data |
| factory | app | `0x20000` | `0x400000` | Firmware |
| coredump | data | `0x420000` | `0x10000` | Core dump on crash |

`tools/flash.sh` writes the bootloader at `0x0`, the partition table at `0x8000`, and
the app at `0x20000`. It does not write the NVS partition. The restore image in
`backup/RESTORE.md` uses a different, older table, so it does not match this layout.

## Data stores

NVS namespaces and keys, as the source uses them:

| Namespace | Key | Contents | Source |
|---|---|---|---|
| `app` | `cfg` | Configuration | `main/config.c` |
| `app` | `base` | Empty-room baseline record | `main/sensing.c` |
| `wifi` | `ssid`, `pass` | Joined network name and password (plaintext) | `main/sensing.c` |
| `fido` | `msec` | Master secret, plaintext until hardening | `main/fido/store.c` |
| `fido` | `pin` | PIN verifier, encrypted and authenticated | `main/fido/store.c` |
| `fido` | `ctr` | Signature counter, written in batches | `main/fido/store.c` |
| `fido` | `c00` to `c15` | Resident credential records (up to 16) | `main/fido/store.c` |

The crash counter and safe-mode flag are in RTC no-init memory, not in NVS. They survive
a panic but are not kept across a power loss.

## WebSocket feed

`GET /ws` pushes one JSON frame every 100 ms (10 Hz). The frame is built by
`sensing_snapshot_json()` in `main/sensing.c`. Fields:

| Field | Type and values |
|---|---|
| `t` | integer timestamp |
| `ch` | Wi-Fi channel, 1 to 13 |
| `motion` | number, 0 to 1 |
| `presence` | `present` or `away` |
| `away_in` | seconds until away, or `null` |
| `why` | `motion`, `breathing`, `baseline`, or `null` |
| `breath` | `{bpm, conf}`, or `null` |
| `baseline` | `{set, dev}`, or `{set: false, capturing: true, left}` while capturing |
| `aps` | access points (at most 12, strongest first); see below |
| `ble` | tracker-kind advertisements; see below |
| `alerts` | `{kind, id, label, detail, age}`; `kind` is `deauth`, `evil_twin`, or `tracker` |
| `link` | `{mode, state, ssid}`; `mode` is `passive` or `joined`; `state` is `off`, `connecting`, `connected`, or `failed` |
| `fido` | `{state}`; `state` is `idle`, `busy`, or `waiting_touch` |

Each `aps` entry has `id` (12 hex characters), `ssid`, `ch`, `rssi`, `dist`, `motion`,
`rate`, `flag` (`deauth`, `twin`, `spoof`, or `null`), `trusted` (boolean), `csi` (64
values), and `pdp` (16 values). If a frame is too large, the fallback omits `csi` and
`pdp`.

Each `ble` entry has `id`, `name`, `rssi`, `dist`, `kind` (`airtag`, `findmy`, `tile`,
`smarttag`, or `null`), and `seen`.

A fault frame has `stub: true` and a `fault` string, with zero motion and empty lists.
Faults are set by `sensing_fault()`, for example `safe mode after repeated crashes`,
`out of memory`, or `task create failed`.

`tools/ws_check.py` validates frames against this contract.

## REST endpoints

Auth rules in this table:

- **Host** must be `192.168.7.1`, optionally with port 80. Every request needs it.
- **Origin absent or exact**: a GET may carry no `Origin`, or `Origin: http://192.168.7.1`.
- **POST rules**: exact `Origin: http://192.168.7.1` and `Content-Type: application/json`.

| Method | Path | Auth | Notes |
|---|---|---|---|
| GET | `/api/config` | Origin absent or exact | Current settings |
| POST | `/api/config` | POST rules | Validated and written at most once per second |
| GET | `/api/status` | Origin absent or exact | Firmware version (`fw`), presence, sensing status |
| POST | `/api/calibrate` | POST rules | Records the baseline over 10 s. `?clear=1` clears it. 5 s rate limit |
| POST | `/api/lock` | POST rules | Sends the lock shortcut. 5 s rate limit |
| POST | `/api/reboot` | POST rules | `?mode=normal` or `?mode=download`. Release download: answers 202 with a confirm message and waits for BOOT held 3 s within 30 s. Returns 409 if a FIDO op or another confirmation is pending. Dev builds reboot at once |
| GET | `/api/fido` | Origin absent or exact | `credentials`, `count`, `hardened`, `pin_set`, `pin_retries`, `op`, `op_state` |
| GET | `/api/log` | Origin absent or exact | Dev builds only (`CONFIG_DEV_BACKDOOR`) |
| POST | `/api/fido/reset` | POST rules | 202. Admin op waits up to 30 s for a BOOT press |
| POST | `/api/fido/harden` | POST rules | Body must be exactly `{"confirm":"BURN"}`. 202. BOOT press required |
| GET | `/api/wifi` | Origin absent or exact | Joined network state |
| POST | `/api/wifi` | POST rules | `ssid` 1 to 32 bytes; `pass` empty or 8 to 63 bytes. `?clear=1` forgets the network. 5 s rate limit |
| GET | `/ws` | Host and exact Origin, checked before the handshake | WebSocket feed. Client frames are discarded. A frame over 128 bytes closes the session. At most 4 clients |
| GET | `/*` | Host | Static dashboard files, gzip, `Cache-Control: no-cache` |

Every response carries `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`,
`Referrer-Policy: no-referrer`, and a Content-Security-Policy with `default-src 'self'`,
a script hash for the inline import map, `connect-src 'self' ws://192.168.7.1`, and
`frame-ancestors 'none'`. `/api/` responses carry `Cache-Control: no-store`.

Dev-only: `/api/log`, and the immediate download mode on `/api/reboot`. Both depend on
`CONFIG_DEV_BACKDOOR`.

## Threading and timing

- The WebSocket feed publishes a frame every 100 ms.
- The sensing tick runs every 100 ms (`TICK_MS`).
- Lock actions from HTTP are rate-limited to one per 5 s. A failed lock send is retried
  every 2 s while the host is away (`LOCK_RETRY_US`, `main/lock.h`).
- Admin FIDO operations run one at a time under the FIDO command lock.

Tunables are at the top of each file. [SENSING.md](SENSING.md) lists the sensing and
threat ones.
