# Security policy

S3 Sentinel is an experimental, uncertified project. It has not been audited.

## Reporting a vulnerability

Please do not open a public issue for a security problem. Report privately through the
repository's security advisory feature.

Include the firmware version (`/api/status` reports it), the host operating system,
and the steps to reproduce. No response time is promised for this 0.1.0 release.

## Scope

In scope: the firmware in `main/`, the dashboard in `web/`, and the host tools in
`tools/`.

Out of scope: the host operating system, the Wi-Fi network the device joins, and
physical attacks that need the device in hand, unless the firmware makes them worse
than described below.

## Security model of the HTTP server

This summary follows the header comment at the top of `main/http.c`. Each sentence
below was checked against the code.

- **Reachability.** The HTTP listener is bound to the USB NCM network interface with
  `SO_BINDTODEVICE`. If that bind fails, the server logs an error and relies on the
  address checks alone. The address checks refuse any connection whose local address is
  not `192.168.7.1`, or whose peer is not in `192.168.7.0/24`. In joined (Wi-Fi station)
  mode, a station lease that overlaps `192.168.7.0/24` is refused (`main/sensing.c`,
  `main/net_policy.h`). Hosts on the Wi-Fi side are not expected to reach the server.
- **Browsers.** Every request must carry `Host: 192.168.7.1`, optionally with port 80.
  This blocks DNS rebinding. POST requests must carry `Origin: http://192.168.7.1` and
  `Content-Type: application/json`. This blocks cross-site forms. Every served response
  sets `X-Frame-Options: DENY` and a Content-Security-Policy with `frame-ancestors 'none'`,
  which blocks clickjacking. WebSocket connections must carry the exact Origin.
- **Local processes: residual risk.** Any program on the host that the device is
  plugged into can send the same headers, and so has the same power as the dashboard.
  No token would change this. A token given to the dashboard by GET can be read by the
  same process. A local process can turn auto-lock off, change `lock_os`, join or forget
  Wi-Fi networks, recalibrate, read presence and radio data, and trigger a lock (one per
  5 seconds). Actions with effects beyond the host session need a physical BOOT press:
  ROM download mode (release builds: BOOT held for 3 seconds within a 30-second window),
  FIDO reset, and FIDO hardening.
- **Release builds.** `GET /api/log` is not in release builds. It exists only when
  `CONFIG_DEV_BACKDOOR` is set. Dev builds also restore immediate download mode, with
  no BOOT hold.

### CTAPHID vendor commands

- `0x51` with the payload `DOWNLOAD` reboots into ROM download mode. In release builds it
  needs BOOT held for 3 seconds within a 30-second window, the same as the HTTP route. In
  dev builds it reboots at once (`main/fido/fido.c`).
- `0x52` returns the RAM log. It is compiled only with `CONFIG_DEV_BACKDOOR`.

## Things the default build does not protect

- **No flash encryption and no secure boot.** `sdkconfig.defaults` enables neither.
  Anyone with physical access can read the flash, including the FIDO master secret until
  hardening is run, and can reflash the device.
- **FIDO master secret in NVS.** Until hardening, the master secret is stored as
  plaintext in the NVS namespace `fido`, key `msec`.
- **FIDO PIN is guessable offline from a flash dump.** Without flash encryption, a dump
  of the flash lets an attacker guess the PIN offline, with no retry limit. The PIN
  retry counter (8 attempts) protects only against online guessing over USB. Hardening
  moves the master key out of flash and so removes this exposure.
- **FIDO hardening is irreversible.** `POST /api/fido/harden` with `{"confirm":"BURN"}`
  and a BOOT press burns an eFuse key block as `HMAC_UP` and erases resident
  credentials. An eFuse burn cannot be undone. See [docs/FIDO.md](docs/FIDO.md).
- **Attestation is self-signed.** Packed self attestation for CTAP2 has no certificate
  chain. U2F uses a fixed batch key that is public and identifies no device. Relying
  parties cannot verify the device's make.
- **Wi-Fi credentials** are stored in NVS (namespace `wifi`, keys `ssid` and `pass`)
  without encryption.
- **Core dumps** are written to the flash partition at `0x420000` on a crash. They can
  contain memory contents, including key material held in RAM.
- **Dev and test options** weaken the device: `CONFIG_DEV_BACKDOOR`,
  `CONFIG_DEV_AUTORECOVER`, and `CONFIG_FIDO_TEST_AUTO_UP`. Never flash a dev or test
  build onto a device that holds real credentials.

## Dependencies

Third-party code and its licenses are listed in `THIRD_PARTY_NOTICES.md`. Security fixes
in ESP-IDF, TinyUSB, or mbedTLS are not tracked by this project beyond the versions
pinned in `dependencies.lock` and the ESP-IDF version named in `docs/BUILDING.md`.
