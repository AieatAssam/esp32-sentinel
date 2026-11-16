#!/usr/bin/env python3
"""Records raw BLE advertisements from a development build (GET /api/ble_raw) for offline analysis.

Usage: tools/ble_capture.py OUT_FILE [SECONDS]   (default 300)
OUT_FILE receives the raw 45-byte records (layout: sensing_ble_raw_t in main/sensing.h), appended
as they arrive. Keep captures outside the repository: they hold MAC addresses. Standard library only.
"""
import struct
import sys
import time
import urllib.request

URL = "http://192.168.7.1/api/ble_raw"
REC = 45


def main():
    out = sys.argv[1]
    seconds = float(sys.argv[2]) if len(sys.argv) > 2 else 300.0
    total = dropped = errors = 0
    t_end = time.monotonic() + seconds
    last = time.monotonic()
    with open(out, "ab") as f:
        while time.monotonic() < t_end:
            try:
                body = urllib.request.urlopen(urllib.request.Request(URL, headers={"Host": "192.168.7.1"}), timeout=5).read()
            except OSError as e:
                errors += 1
                print(f"request failed ({errors} so far): {e}", file=sys.stderr, flush=True)
                time.sleep(1.0)
                continue
            recs = body[4:]
            if len(recs) % REC:
                errors += 1
                print(f"bad body length {len(recs)} (not a multiple of {REC}), skipped", file=sys.stderr, flush=True)
                time.sleep(0.5)
                continue
            dropped += struct.unpack_from("<I", body)[0]
            f.write(recs)
            total += len(recs) // REC
            if time.monotonic() - last >= 10:
                last = time.monotonic()
                print(f"{seconds - (t_end - last):6.0f} s  records {total}  dropped {dropped}", flush=True)
            time.sleep(0.5)
    print(f"done: {total} records, {dropped} dropped, {errors} request errors, in {out}")


if __name__ == "__main__":
    main()
