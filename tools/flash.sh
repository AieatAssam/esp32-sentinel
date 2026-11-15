#!/usr/bin/env bash
# Flashes the built firmware: bootloader, partition table, app.
# Requires a verified backup unless FORCE_NO_BACKUP=1 is set.
#
# Usage: [BUILD=dir] tools/flash.sh [PORT]
#   PORT defaults to the first /dev/cu.usbmodem* device.
#   BUILD defaults to ./build (the idf.py -B directory to flash).
# Release firmware asks for a BOOT press before it enters download mode;
# dev firmware (CONFIG_DEV_BACKDOOR, sdkconfig.dev) does not.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="${BUILD:-$ROOT/build}"
BACKUP="$ROOT/backup/original-flash-0x0-0x200000.bin"
RESTORE="$ROOT/backup/RESTORE.md"
DEVICE_IP="192.168.7.1"
ORIGIN="http://${DEVICE_IP}"
ESPTOOL="${ESPTOOL:-esptool}"
CHIP="esp32s3"

die() { echo "flash.sh: $*" >&2; exit 1; }

# 1. Backup gate.
if [ "${FORCE_NO_BACKUP:-0}" != "1" ]; then
    [ -s "$BACKUP" ] && [ -s "$RESTORE" ] || \
        die "no verified backup ($BACKUP and $RESTORE). Create it first, or set FORCE_NO_BACKUP=1 to override."
fi

# 2. Build artifacts.
BOOT_BIN="$BUILD/bootloader/bootloader.bin"
PT_BIN="$BUILD/partition_table/partition-table.bin"
APP_BIN="$(ls "$BUILD"/*.bin 2>/dev/null | grep -v -e bootloader -e partition-table | head -n 1 || true)"
for f in "$BOOT_BIN" "$PT_BIN" "$APP_BIN"; do
    [ -s "$f" ] || die "missing build artifact $f (run idf.py build)"
done

# 3-4. Get the board into ROM download mode. The app has no CDC port, so a
# /dev/cu.usbmodem* port only exists once the ROM download port is up: its
# appearance is the signal for every stage below.
port_now() { ls /dev/cu.usbmodem* 2>/dev/null | head -n 1 || true; }
wait_port() {   # wait_port SECONDS
    for _ in $(seq 1 "$1"); do
        PORT="$(port_now)"
        [ -n "$PORT" ] && return 0
        sleep 1
    done
    return 1
}

PORT="${1:-}"
[ -n "$PORT" ] || PORT="$(port_now)"
if [ -n "$PORT" ]; then
    echo "download port $PORT already present"
else
    # a. HTTP reboot endpoint (needs a working USB network link). Dev firmware
    #    reboots at once; release firmware answers 202 and waits for BOOT held 3 s.
    echo "requesting download mode via http://$DEVICE_IP/api/reboot"
    if REPLY="$(curl -fsS -m 5 -X POST \
            -H "Origin: $ORIGIN" -H "Content-Type: application/json" \
            -d '{}' "http://$DEVICE_IP/api/reboot?mode=download")" && {
            case "$REPLY" in
                *confirm*) echo "press BOOT on the device now and hold it for 3 s (30 s window)"; wait_port 40 ;;
                *) wait_port 20 ;;
            esac; }; then
        echo "download mode via HTTP"
    # b. CTAPHID vendor command on the FIDO interface (no network needed).
    elif echo "HTTP failed, trying tools/hidctl.py download" && \
            "${PYTHON:-python3}" "$ROOT/tools/hidctl.py" download && wait_port 20; then
        echo "download mode via FIDO HID"
    # c. CONFIG_DEV_AUTORECOVER firmware drops to download mode 60 s after boot
    #    when no HTTP request arrived.
    elif echo "HID failed, waiting up to 75 s for dev auto-recover" && wait_port 75; then
        echo "download mode via auto-recover"
    else
        die "board not in download mode: HTTP reboot, tools/hidctl.py download and the 75 s auto-recover wait all failed. Hold BOOT and replug the board, then rerun."
    fi
fi

sleep 1   # let the freshly enumerated ROM port settle

# 5. Flash. --before no-reset keeps the ROM in download mode.
echo "flashing $PORT"
"$ESPTOOL" --chip "$CHIP" --port "$PORT" --before no-reset --after no-reset \
    write-flash 0x0 "$BOOT_BIN" 0x8000 "$PT_BIN" 0x20000 "$APP_BIN" \
    || die "write-flash failed"

# 6. Hard reset into the new firmware.
"$ESPTOOL" --chip "$CHIP" --port "$PORT" --before no-reset --after watchdog-reset read-mac >/dev/null \
    || echo "flash.sh: hard reset via esptool failed, reset the board manually"

# 7. Wait for the app to answer.
echo "waiting for http://$DEVICE_IP/api/status"
for _ in $(seq 1 30); do
    if curl -fsS -m 3 -H "Origin: $ORIGIN" "http://$DEVICE_IP/api/status" >/dev/null 2>&1; then
        echo "flash.sh: firmware is up"
        exit 0
    fi
    sleep 1
done
die "firmware did not answer on $DEVICE_IP after flashing (run tools/bootlog.py to see the console)"
