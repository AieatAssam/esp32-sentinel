#!/usr/bin/env python3
"""Talks to the S3 Sentinel over its FIDO HID interface, with no network needed.

Usage:
  tools/hidctl.py download   reboot the board into ROM download mode (vendor cmd 0x51)
  tools/hidctl.py log        print the firmware's RAM log ring (vendor cmd 0x52)

Release firmware asks for BOOT held 3 s (within 30 s) before entering download mode and has
no log command. Firmware built with CONFIG_DEV_BACKDOOR (sdkconfig.dev) needs no press.

Needs python-fido2 (python3 -m pip install fido2). Exit code 0 on success,
1 if the device is missing or refuses, 2 if fido2 is not installed.
"""
import sys

try:
    from fido2.hid import CtapHidDevice
except ImportError:
    print("hidctl.py: python-fido2 missing (python3 -m pip install fido2)", file=sys.stderr)
    sys.exit(2)

VID, PID = 0x303A, 0x4001
CMD_DOWNLOAD = 0x51
CMD_LOG = 0x52
MAX_MSG = 7609   # CTAPHID_MAX_MSG in firmware; a shorter reply is the last log page


def find_device():
    for dev in CtapHidDevice.list_devices():
        if dev.descriptor.vid == VID and dev.descriptor.pid == PID:
            return dev
    return None


def main() -> int:
    if len(sys.argv) != 2 or sys.argv[1] not in ("download", "log"):
        print(__doc__, file=sys.stderr)
        return 1
    dev = find_device()
    if dev is None:
        print(f"hidctl.py: no CTAPHID device {VID:04x}:{PID:04x} found", file=sys.stderr)
        return 1
    try:
        if sys.argv[1] == "download":
            prompted = []

            def on_keepalive(status):
                if not prompted:   # the device is waiting for BOOT (release firmware)
                    prompted.append(1)
                    print("hidctl.py: press BOOT on the device now and hold it for 3 s (30 s window)", file=sys.stderr, flush=True)

            reply = dev.call(CMD_DOWNLOAD, b"DOWNLOAD", on_keepalive=on_keepalive)
            print(f"hidctl.py: device answered {reply!r}, rebooting into download mode")
            return 0 if reply == b"OK" else 1
        log, off = b"", 0
        while True:
            page = dev.call(CMD_LOG, off.to_bytes(4, "big"))
            log += page
            off += len(page)
            if len(page) < MAX_MSG:
                break
        sys.stdout.write(log.decode("utf-8", "replace"))
        return 0
    except Exception as e:  # CtapError, OSError, ConnectionFailure: all mean "did not work"
        print(f"hidctl.py: {sys.argv[1]} failed: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
