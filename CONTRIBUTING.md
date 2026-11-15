# Contributing

Thanks for looking at S3 Sentinel. Bug reports, reviews, and pull requests are welcome.
Please read [SECURITY.md](SECURITY.md) first if your change touches authentication,
the HTTP server, FIDO, or download and flashing paths.

## Before you start

- Open an issue for anything larger than a small fix, so the approach can be agreed.
- Security problems go to a private advisory, not to an issue (see SECURITY.md).

## Setting up

Follow [docs/BUILDING.md](docs/BUILDING.md). For dashboard work you do not need
hardware: open `web/index.html?mock=1`.

## Making a change

- Keep changes focused. One concern per pull request.
- Match the style of the file you edit. The repository has `.editorconfig`.
- C code follows the ESP-IDF style used in `main/`. Keep `ESP_LOGx` tags consistent.
- Do not commit generated files: `build*/`, `sdkconfig`, `managed_components/`, or
  anything under `backup/` that is binary.
- If you change `web/`, rebuild the firmware, because the dashboard is embedded.
- If you change behaviour that a host test covers, run the test. If you add logic with
  a branch or a loop, add a small check next to the existing tests in `tools/`.

## Checks

Run these before you open a pull request. CI runs the host tests, the dashboard syntax
check, and the release and development builds. CI has not run yet (see `.github/workflows/build.yml`).

```sh
. "$IDF_PATH/export.sh"
idf.py -B build_rel -D SDKCONFIG=build_rel/sdkconfig -D SDKCONFIG_DEFAULTS="sdkconfig.defaults" build
idf.py -B build_dev -D SDKCONFIG=build_dev/sdkconfig -D SDKCONFIG_DEFAULTS="sdkconfig.defaults;sdkconfig.dev" build
idf.py -B build_test -D SDKCONFIG=build_test/sdkconfig -D SDKCONFIG_DEFAULTS="sdkconfig.defaults;sdkconfig.dev;sdkconfig.test" build
cc -Wall -Werror -I main tools/lock_policy_test.c -o "$TMPDIR/lock_policy_test" && "$TMPDIR/lock_policy_test"
cc -Wall -Werror -I main tools/net_policy_test.c -o "$TMPDIR/net_policy_test" && "$TMPDIR/net_policy_test"
cc -Wall -Werror -I main tools/threats_test.c main/threats.c -o "$TMPDIR/threats_test" && "$TMPDIR/threats_test"
node --check web/js/*.js
```

The three `idf.py` lines build the release, development, and test configurations. The
release build is the one that matters for shipping. See
[docs/BUILDING.md](docs/BUILDING.md#build-configurations).

## Pull requests

Use the pull request template. Describe what changed and why, what you tested, and
on which hardware. Say plainly what you did not test.

## Licensing

By contributing you agree that your contribution is licensed under the MIT License in
[LICENSE](LICENSE). Do not add third-party code without its license text, and record
it in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) and `licenses/`.

## Conduct

Participation is governed by the [Code of Conduct](CODE_OF_CONDUCT.md).
