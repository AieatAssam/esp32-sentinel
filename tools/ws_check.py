#!/usr/bin/env python3
"""Validate the sensing WebSocket feed (ws://192.168.7.1/ws) against the frame contract.

Usage: tools/ws_check.py [SECONDS]   (default 20). Needs the `websockets` package.
Prints frame rate, frame size, AP count, per-AP CSI rate, motion and breath statistics.
Exit code 1 when any frame breaks the contract.
"""
import asyncio
import json
import statistics
import sys
import time

URL = "ws://192.168.7.1/ws"
ORIGIN = "http://192.168.7.1"
FIDO_STATES = {"idle", "busy", "waiting_touch"}
LINK_STATES = {"off", "connecting", "connected", "failed"}


def _is_num(v):
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def check(f):
    """Returns a list of contract violations for one parsed frame."""
    e = []
    if "stub" in f:
        # Only a sensing fault (safe mode, out of memory) may send stub frames, and then with a reason.
        if f.get("stub") is not True or not isinstance(f.get("fault"), str) or not f["fault"]:
            e.append("stub without fault")
        if f.get("aps") != [] or f.get("presence") != "present" or f.get("away_in") is not None:
            e.append("fault frame not idle")
        return e
    if not _is_int(f.get("t")):
        e.append("t not int")
    if not (_is_int(f.get("ch")) and 1 <= f["ch"] <= 13):
        e.append("ch out of range")
    m = f.get("motion")
    if not (_is_num(m) and 0 <= m <= 1):
        e.append("motion out of range")
    nr = f.get("near", "missing")
    if nr is not None and not (_is_num(nr) and 0 <= nr <= 1):
        e.append("near bad")
    if f.get("presence") not in ("present", "away"):
        e.append("presence bad")
    aw = f.get("away_in", "missing")
    if aw is not None and not (_is_int(aw) and aw >= 0):
        e.append("away_in bad")
    if f.get("why") not in (None, "motion", "breathing", "baseline"):
        e.append("why bad")
    b = f.get("breath", "missing")
    if b is not None:
        if not isinstance(b, dict) or not _is_num(b.get("bpm")) or not (_is_num(b.get("conf")) and 0 <= b["conf"] <= 1):
            e.append("breath bad")
    bl = f.get("baseline")
    if not isinstance(bl, dict) or not isinstance(bl.get("set"), bool):
        e.append("baseline bad")
    elif bl.get("capturing"):
        if not (bl.get("set") is False and _is_int(bl.get("left"))):
            e.append("baseline capturing bad")
    elif not (_is_num(bl.get("dev")) and 0 <= bl["dev"] <= 1):
        e.append("baseline dev bad")
    aps = f.get("aps")
    if not isinstance(aps, list) or len(aps) > 12:
        e.append("aps not list<=12")
        aps = []
    for a in aps:
        if not isinstance(a.get("id"), str) or not a.get("id"):
            e.append("ap id bad")
        if not isinstance(a.get("ssid"), str) or not _is_int(a.get("ch")) or not _is_int(a.get("rssi")):
            e.append("ap fields bad")
        if not _is_num(a.get("dist")) or not (_is_num(a.get("motion")) and 0 <= a["motion"] <= 1):
            e.append("ap dist/motion bad")
        if not _is_num(a.get("rate")) or a["rate"] < 0:
            e.append("ap rate bad")
        if a.get("flag") not in (None, "deauth", "twin", "spoof"):
            e.append("ap flag bad")
        if not isinstance(a.get("trusted"), bool):
            e.append("ap trusted bad")
        c, p = a.get("csi"), a.get("pdp")
        if not (isinstance(c, list) and len(c) == 64 and all(_is_int(x) and 0 <= x <= 255 for x in c)):
            e.append("ap csi bad")
        if not (isinstance(p, list) and len(p) == 16 and all(_is_int(x) and 0 <= x <= 255 for x in p)):
            e.append("ap pdp bad")
    ble = f.get("ble")
    if not isinstance(ble, list) or len(ble) > 24:
        e.append("ble not list<=24")
        ble = []
    for d in ble:
        if not isinstance(d.get("id"), str) or not isinstance(d.get("name"), str):
            e.append("ble id/name bad")
        if not _is_int(d.get("rssi")) or not _is_num(d.get("dist")):
            e.append("ble rssi/dist bad")
        if d.get("kind") not in (None, "airtag", "findmy", "tile", "smarttag") or not (_is_int(d.get("seen")) and d["seen"] >= 0):
            e.append("ble kind/seen bad")
    alerts = f.get("alerts")
    if not isinstance(alerts, list) or len(alerts) > 8:
        e.append("alerts not list<=8")
        alerts = []
    for al in alerts:
        if al.get("kind") not in ("deauth", "evil_twin", "tracker"):
            e.append("alert kind bad")
        if not all(isinstance(al.get(k), str) for k in ("id", "label", "detail")):
            e.append("alert text bad")
        if not (_is_int(al.get("age")) and al["age"] >= 0):
            e.append("alert age bad")
    fido = f.get("fido")
    if not isinstance(fido, dict) or fido.get("state") not in FIDO_STATES:
        e.append("fido state bad")
    link = f.get("link")
    if not isinstance(link, dict) or link.get("mode") not in ("passive", "joined"):
        e.append("link mode bad")
    elif link.get("state") not in LINK_STATES:
        e.append("link state bad")
    elif not (link.get("ssid") is None or isinstance(link.get("ssid"), str)):
        e.append("link ssid bad")
    return e


async def run(seconds):
    import websockets  # here, so check() can be imported without the package
    sizes, times, aps_n, motion = [], [], [], []
    rate_sum, rate_n = {}, {}
    breath, errors = [], []
    links = {}
    flags, ble_kinds, alert_kinds, alert_samples = {}, {}, {}, []
    frames = 0
    kwargs = {"additional_headers": {"Origin": ORIGIN}}
    try:
        ws = await websockets.connect(URL, open_timeout=10, **kwargs)
    except TypeError:
        ws = await websockets.connect(URL, open_timeout=10, extra_headers={"Origin": ORIGIN})
    async with ws:
        t_end = time.monotonic() + seconds
        while time.monotonic() < t_end:
            raw = await asyncio.wait_for(ws.recv(), timeout=5)
            times.append(time.monotonic())
            text = raw if isinstance(raw, str) else raw.decode()
            sizes.append(len(text.encode()))
            frames += 1
            try:
                f = json.loads(text)
            except ValueError:
                errors.append("frame %d not JSON" % frames)
                continue
            errs = check(f)
            if errs and len(errors) < 10:
                errors.append("frame %d: %s" % (frames, ", ".join(sorted(set(errs)))))
            elif errs:
                errors.append("x")
            aps_n.append(len(f.get("aps", [])))
            motion.append(f.get("motion", 0.0))
            for a in f.get("aps", []):
                if not isinstance(a, dict):
                    continue
                if "id" in a and isinstance(a.get("rate"), (int, float)):
                    rate_sum[a["id"]] = rate_sum.get(a["id"], 0.0) + a["rate"]
                    rate_n[a["id"]] = rate_n.get(a["id"], 0) + 1
                if a.get("flag"):
                    flags[a["flag"]] = flags.get(a["flag"], 0) + 1
            for d in f.get("ble", []):
                if d.get("kind"):
                    ble_kinds[d["kind"]] = ble_kinds.get(d["kind"], 0) + 1
            for al in f.get("alerts", []):
                alert_kinds[al["kind"]] = alert_kinds.get(al["kind"], 0) + 1
                if len(alert_samples) < 3 and al not in alert_samples:
                    alert_samples.append(al)
            b = f.get("breath")
            if b:
                breath.append((b["bpm"], b["conf"]))
            lk = f.get("link")
            if isinstance(lk, dict):
                key = "%s/%s" % (lk.get("mode"), lk.get("state"))
                links[key] = links.get(key, 0) + 1

    dur = times[-1] - times[0] if len(times) > 1 else 0.0
    print("frames: %d over %.1f s -> %.2f frames/s" % (frames, dur, (frames - 1) / dur if dur else 0.0))
    if sizes:
        print("frame bytes: min %d mean %.0f max %d" % (min(sizes), statistics.mean(sizes), max(sizes)))
    if aps_n:
        print("AP count: min %d mean %.1f max %d" % (min(aps_n), statistics.mean(aps_n), max(aps_n)))
    for ap_id in sorted(rate_sum):
        print("  AP %s mean CSI rate %.2f/s (in %d frames)" % (ap_id, rate_sum[ap_id] / rate_n[ap_id], rate_n[ap_id]))
    if len(motion) >= 2:
        q = statistics.quantiles(motion, n=10)
        print("motion: min %.3f p10 %.3f median %.3f p90 %.3f max %.3f mean %.3f"
              % (min(motion), q[0], statistics.median(motion), q[8], max(motion), statistics.mean(motion)))
    elif motion:
        print("motion: %.3f (one frame)" % motion[0])
    if breath:
        bpms = [b for b, _ in breath]
        confs = [c for _, c in breath]
        print("breath: %d frames with estimate; bpm min %.1f mean %.1f max %.1f; conf max %.2f"
              % (len(breath), min(bpms), statistics.mean(bpms), max(bpms), max(confs)))
    else:
        print("breath: null in all frames")
    if links:
        print("link (mode/state frame counts): " + ", ".join("%s=%d" % kv for kv in sorted(links.items())))
    print("AP flags (frame counts): " + (", ".join("%s=%d" % kv for kv in sorted(flags.items())) or "none"))
    print("BLE kinds (frame counts): " + (", ".join("%s=%d" % kv for kv in sorted(ble_kinds.items())) or "none"))
    print("alerts (frame counts): " + (", ".join("%s=%d" % kv for kv in sorted(alert_kinds.items())) or "none"))
    for al in alert_samples:
        print("  alert sample: %s" % json.dumps(al, ensure_ascii=False))
    bad = [x for x in errors if x != "x"]
    total_bad = len(errors)
    print("contract violations: %d" % total_bad)
    for x in bad:
        print("  " + x)
    return 1 if total_bad else 0


if __name__ == "__main__":
    secs = float(sys.argv[1]) if len(sys.argv) > 1 else 20.0
    sys.exit(asyncio.run(run(secs)))
