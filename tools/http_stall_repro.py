#!/usr/bin/env python3
"""Slow-client stall test for the device web server (192.168.7.1).

Opens WebSocket clients that complete the handshake and then never read (a backgrounded
browser tab), plus plain TCP connections that never send a request, then checks that the REST
API keeps answering and that a well-behaved WebSocket client keeps getting ~10 frames/s.

Usage: tools/http_stall_repro.py [--stuck-ws N] [--idle N] [--seconds S] [--release]
  --release  close the stuck clients halfway and check that the server is still fine after.
Exit 0 when every probe answered within --probe-timeout and the good client (which reconnects like
the dashboard) was below 5 frames/s for at most 3 seconds.
Standard library only.
"""
import argparse
import base64
import os
import socket
import sys
import threading
import time

HOST = "192.168.7.1"
PORT = 80
ORIGIN = "http://192.168.7.1"


def ws_open(rcvbuf=None, timeout=5):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if rcvbuf:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rcvbuf)   # small window: fills fast
    s.settimeout(timeout)
    s.connect((HOST, PORT))
    key = base64.b64encode(os.urandom(16)).decode()
    s.sendall((f"GET /ws HTTP/1.1\r\nHost: {HOST}\r\nOrigin: {ORIGIN}\r\nUpgrade: websocket\r\n"
               f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = s.recv(1)
        if not chunk:
            raise ConnectionError("closed during handshake")
        buf += chunk
    if b" 101 " not in buf.split(b"\r\n", 1)[0]:
        raise ConnectionError(buf.split(b"\r\n", 1)[0].decode(errors="replace"))
    return s


def probe(timeout):
    """GET /api/status on a fresh connection. Returns seconds taken, or None on failure."""
    t0 = time.monotonic()
    try:
        with socket.create_connection((HOST, PORT), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(f"GET /api/status HTTP/1.1\r\nHost: {HOST}\r\nConnection: close\r\n\r\n".encode())
            f = s.makefile("rb")             # httpd ignores Connection: close; read by length
            status = f.readline()
            length = 0
            while (line := f.readline()) not in (b"\r\n", b""):
                if line.lower().startswith(b"content-length:"):
                    length = int(line.split(b":")[1])
            if len(f.read(length)) != length:
                return None
        return time.monotonic() - t0 if status.startswith(b"HTTP/1.1 200") else None
    except OSError:
        return None


class GoodClient(threading.Thread):
    """Reads WS frames as fast as they come and counts them."""
    def __init__(self):
        super().__init__(daemon=True)
        self.frames = 0
        self.alive = True
        self.err = None

    def run(self):
        self.reconnects = 0
        while self.alive:                     # reconnects like the dashboard does
            try:
                s = ws_open(timeout=10)
                f = s.makefile("rb")
                while self.alive:
                    h = f.read(2)
                    if len(h) < 2:
                        raise ConnectionError("closed")
                    n = h[1] & 0x7F
                    if n == 126:
                        n = int.from_bytes(f.read(2), "big")
                    elif n == 127:
                        n = int.from_bytes(f.read(8), "big")
                    f.read(n)
                    self.frames += 1
            except OSError as e:
                self.err = str(e) or type(e).__name__
                self.reconnects += 1
                time.sleep(1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--stuck-ws", type=int, default=4)
    ap.add_argument("--idle", type=int, default=6)
    ap.add_argument("--seconds", type=int, default=60)
    ap.add_argument("--probe-timeout", type=float, default=3.0)
    ap.add_argument("--release", action="store_true")
    a = ap.parse_args()

    good = GoodClient()
    good.start()
    time.sleep(2)

    stuck = []
    for i in range(a.stuck_ws):
        try:
            stuck.append(ws_open(rcvbuf=2048))
        except OSError as e:
            print(f"stuck ws {i}: {e}")
    for i in range(a.idle):
        try:
            stuck.append(socket.create_connection((HOST, PORT), timeout=5))
        except OSError as e:
            print(f"idle socket {i}: {e}")
    print(f"opened {len(stuck)} stuck connections; good client frames so far {good.frames}")

    fails, worst, last_frames, low_fps = 0, 0.0, good.frames, 0
    t_end = time.monotonic() + a.seconds
    released = False
    while time.monotonic() < t_end:
        if a.release and not released and time.monotonic() > t_end - a.seconds / 2:
            for s in stuck:
                s.close()
            released = True
            print("released stuck clients")
        t0 = time.monotonic()
        dt = probe(a.probe_timeout)
        if dt is None:
            fails += 1
        else:
            worst = max(worst, dt)
        print(f"t={a.seconds - (t_end - time.monotonic()):5.1f}s status={'FAIL' if dt is None else f'{dt*1000:.0f}ms'}"
              f" good_ws_frames={good.frames} reconnects={good.reconnects}", flush=True)
        time.sleep(max(0.0, 1.0 - (time.monotonic() - t0)))
        rate = (good.frames - last_frames) / max(time.monotonic() - t0, 1e-3)
        last_frames = good.frames
        if rate < 5:
            low_fps += 1
    good.alive = False
    for s in stuck:
        s.close()
    print(f"probes failed: {fails}, worst probe: {worst*1000:.0f} ms, seconds with good client < 5 fps: {low_fps},"
          f" good client reconnects: {good.reconnects}")
    ok = fails == 0 and low_fps <= 3
    print("PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
