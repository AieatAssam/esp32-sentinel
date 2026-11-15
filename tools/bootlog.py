#!/usr/bin/env python3
"""Captures the app console (USB Serial/JTAG secondary console) after a reset.

Usage: tools/bootlog.py [PORT] [SECONDS]
  1. Resets the chip out of ROM download mode with esptool watchdog-reset.
  2. Reads the port for SECONDS (default 12), reopening it whenever it re-enumerates.
Use it when the device does not come up. Once the app's USB stack runs, the JTAG
serial port disappears; then use GET /api/log instead.
Needs pyserial (python3 -m pip install pyserial).
"""
import glob
import os
import subprocess
import sys
import time

import serial

ESPTOOL = os.environ.get("ESPTOOL", "esptool")


def main() -> int:
    ports = glob.glob("/dev/cu.usbmodem*")
    port = sys.argv[1] if len(sys.argv) > 1 else (ports[0] if ports else None)
    seconds = float(sys.argv[2]) if len(sys.argv) > 2 else 12.0
    if not port:
        print("bootlog.py: no /dev/cu.usbmodem* device", file=sys.stderr)
        return 1

    subprocess.run([ESPTOOL, "--chip", "esp32s3", "--port", port, "--before", "no-reset",
                    "--after", "watchdog-reset", "--no-stub", "read-mem", "0x50000000"],
                   capture_output=True)

    out = bytearray()
    handle = None
    end = time.time() + seconds
    while time.time() < end:
        if handle is None:
            try:
                handle = serial.Serial()
                handle.port = port
                handle.baudrate = 115200
                handle.timeout = 0.1
                handle.dtr = False
                handle.rts = False
                handle.open()
            except (serial.SerialException, OSError):
                handle = None
                time.sleep(0.05)
                continue
        try:
            out += handle.read(4096)
        except (serial.SerialException, OSError):
            try:
                handle.close()
            except (serial.SerialException, OSError):
                pass
            handle = None
    if handle is not None:
        handle.close()

    sys.stdout.write(out.decode("utf-8", errors="replace"))
    print(f"\n[bootlog] captured {len(out)} bytes from {port}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
