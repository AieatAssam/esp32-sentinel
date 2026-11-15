## What this changes

<!-- One or two sentences. -->

## Why

<!-- The problem, or the issue this closes (Fixes #...). -->

## How it was tested

- [ ] Release build (`idf.py -B build_rel`, see docs/BUILDING.md), state the ESP-IDF version
- [ ] Host tests (`tools/*_test.c`) pass
- [ ] `node --check web/js/*.js` passes, if `web/` changed
- [ ] Tested on hardware (state the board and the host OS), or "not tested on hardware"

## Notes for review

- [ ] Touches `main/http.c`, `main/fido/`, or the download or flash path: security impact described in the PR
- [ ] Changes a default or a config field: `docs/` and the README table updated
- [ ] Adds a third-party file: `licenses/` and `THIRD_PARTY_NOTICES.md` updated
- [ ] No generated files, binaries, or device data are included
