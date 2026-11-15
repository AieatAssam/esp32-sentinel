# Release checklist

Use this for each tagged release. Tick each item in the release pull request.

## Code and configuration

- [ ] `sdkconfig.defaults` has `CONFIG_DEV_AUTORECOVER=n`.
- [ ] `CONFIG_FIDO_TEST_AUTO_UP` is off in the release configuration (`sdkconfig.defaults`, and not set by `sdkconfig.dev`).
- [ ] `CONFIG_DEV_BACKDOOR` is off in the release configuration. It is set only by `sdkconfig.dev`.
- [ ] The release build (`sdkconfig.defaults` only) is the one published. The development and test builds are for testing and are not published.
- [ ] The vendor CTAPHID command `0x51` is gated in release builds (3 s BOOT hold), and `0x52` is not compiled into release builds. See SECURITY.md.
- [ ] `FW_VERSION` in `main/http.c` matches the version in `CHANGELOG.md` and the tag.
- [ ] No `<!-- TODO -->` markers remain in `docs/` or `README.md`, or each one is listed in the release notes.

## Build

- [ ] Clean builds with ESP-IDF v6.0.1 from empty `build_rel/`, `build_dev/`, and `build_test/` directories, and an empty `managed_components/`. The three configurations are in docs/BUILDING.md.
- [ ] The NCM patch applies cleanly at configure time (the configure step fails otherwise).
- [ ] Host tests pass (commands in docs/BUILDING.md).
- [ ] `node --check web/js/*.js` passes.
- [ ] The CI workflow passes on the tag commit. The workflow has not been run yet.

## Hardware

- [ ] Flash a board with a verified backup (`tools/flash.sh`). Confirm presence, auto-lock, the dashboard, and the FIDO key on that board.
- [ ] `tools/ws_check.py` passes against the device.
- [ ] Restore from the backup image on a spare board and check the SHA-256.

## Licensing and privacy

- [ ] `LICENSE` year is correct.
- [ ] `THIRD_PARTY_NOTICES.md` matches `dependencies.lock` and `licenses/`.
- [ ] Open items in `THIRD_PARTY_NOTICES.md` are resolved, including the Espressif binary libraries.
- [ ] No device MAC, SSID, BSSID, or personal path appears in any tracked file. Run a text search before tagging.
- [ ] `.hallmark/`, `backup/*.bin`, `build*/`, `sdkconfig`, `managed_components/`, and `__pycache__/` are not tracked.

## Publishing

- [ ] `CHANGELOG.md` entry is dated and the "unreleased" label is removed.
- [ ] Tag created (`v0.1.0`), and the release notes link to `CHANGELOG.md` (known limitations) and `SECURITY.md`.
- [ ] Firmware image attached from the CI artifact, with its SHA-256 in the release notes.
