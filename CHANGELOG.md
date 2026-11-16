# Changelog

All notable changes to this project are recorded here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.1.0] - unreleased

### Added

- Initial public source: firmware for the ESP32-S3 USB dongle in `main/`, the
  dashboard in `web/`, and host tools in `tools/`.
- USB composite device: CDC-NCM network (192.168.7.1), FIDO CTAPHID HID interface,
  and boot keyboard interface for the lock shortcut.
- Presence, motion, breathing, and baseline estimates from Wi-Fi CSI and beacon RSSI.
- BLE tracker detection (AirTag, Find My, Tile, SmartTag) through a NimBLE observer.
- Threat heuristics for deauthentication bursts, evil-twin access points, and spoofed
  beacons.
- Auto-lock with a retry policy.
- FIDO2/U2F authenticator (ES256, resident keys, PIN, credential management,
  hmac-secret) with an optional irreversible eFuse hardening step.
- Recovery: boot-loop counter, safe mode in release builds, and a core dump partition.
- Dashboard with a simulated-data mode (`?mock=1`) for development without hardware.
- `GET /api/status` reports internal RAM: `int_free`, `int_min`, `int_largest`, `dma_free`.
  The dashboard's device info shows free internal RAM instead of the PSRAM-dominated total.

### Fixed

- Internal RAM exhaustion. Steady state (joined, BLE scanning, four WebSocket clients) had
  about 7 KB of internal RAM free and 23 bytes at its lowest, and WebSocket handshakes
  failed ("Failed to setup SHA-1"). Large static tables and buffers,
  the log ring and the NimBLE host pools moved to PSRAM: steady state is now about 135 KB
  free, at least 40 KB at its lowest over 30 to 40-minute soaks. See docs/ARCHITECTURE.md, Memory.
- Wi-Fi task crash, seen as a CacheError panic in `wDev_IndicateFrame` or as a "wdt" reset
  with no core dump, about once an hour. With CSI on, the Wi-Fi driver (IDF v6.0.1 libpp)
  copies a received frame as `len - 44 - csi_len` bytes without a check; a buffer no longer
  than its own CSI makes that wrap to about 4 GB. Present before the memory change too. The
  firmware now wraps `esf_buf_alloc` and refuses the buffers for such a frame, so the driver discards
  the frame; dev builds count these as `bad_len` in the "stat csi" log line.
- The HTTP server no longer locks up when clients hold idle connections or stop reading the
  WebSocket.
- The log ring (64 KB, PSRAM) survives a panic or watchdog reset, so `/api/log` on a
  development build shows the lines before it. Dev builds also copy panic output (reason,
  registers, backtrace, core dump progress) into the ring, so a panic whose handler hangs until
  the RTC watchdog still explains itself.

### Known limitations

- Host-side behaviour (the USB NCM network, the lock shortcut, the host tools) is
  untested on platforms other than the developer's own setup. Treat other platforms as
  untested.
- Presence is a heuristic and has not been measured against ground truth in this
  repository.
- Without flash encryption, the FIDO PIN can be guessed offline from a flash dump. The
  8-try retry counter protects only against online guessing over USB. Hardening removes
  this exposure.
- No flash encryption or secure boot in the default configuration.
- The vendor CTAPHID command `0x51` (ROM download mode) is gated in release builds: BOOT
  must be held for 3 s within a 30 s window. The `0x52` log command and the `/api/log`
  route exist only in development builds (`CONFIG_DEV_BACKDOOR`).
- FIDO attestation is self-signed. Relying parties cannot verify the device's make.
- The CI workflow in `.github/workflows/build.yml` has not been run.
