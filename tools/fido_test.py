#!/usr/bin/env python3
"""Host test suite for the FIDO side of the S3 Sentinel (CTAPHID, CTAP2, U2F).

Needs python-fido2 2.x and cryptography (pip install fido2). The board must be reachable over
USB, both as the FIDO HID device and at http://192.168.7.1 (status and reboot endpoints).

  fido_test.py            full suite. On a test build (CONFIG_FIDO_TEST_AUTO_UP, /api/status
                          "test_build": true) every check runs with no button presses and the
                          suite starts by wiping the authenticator (reboot, then CTAP reset in
                          the 10 s window). On any other build only the checks that need no
                          press run, including the 30 s USER_ACTION_TIMEOUT check.
  fido_test.py --wipe     reboot and CTAP reset only (a non-test build needs a BOOT press).

Exit code 0 when every check passed.
"""
import hashlib
import json
import logging
import os
import queue
import struct
import sys
import threading
import time
import urllib.request

from cryptography import x509
from fido2 import cbor
from fido2.attestation import AttestationType, FidoU2FAttestation, PackedAttestation
from fido2.cose import ES256, CoseKey
from fido2.ctap import CtapError
from fido2.ctap1 import ApduError, Ctap1
from fido2.ctap2 import Ctap2
from fido2.ctap2.extensions import HmacSecretExtension
from fido2.ctap2.pin import ClientPin, PinProtocolV1, PinProtocolV2
from fido2.hid import CtapHidDevice, open_connection
from fido2.webauthn import PublicKeyCredentialDescriptor, PublicKeyCredentialRequestOptions

logging.getLogger("fido2.hid").setLevel(logging.CRITICAL)   # RawHid's idle reads log run-loop timeouts

DEVICE = "http://192.168.7.1"
VID, PID = 0x303A, 0x4001
ES256_PARAMS = [{"type": "public-key", "alg": -7}]
FLAG_UP, FLAG_ED = 0x01, 0x80
AAGUID = bytes.fromhex("a3edf53929e05abf64599462327a45e8")
BCAST = 0xFFFFFFFF
CBOR_CMD, MSG_CMD, INIT_CMD, PING_CMD, CANCEL_CMD, ERROR_CMD, KEEPALIVE_CMD = 0x10, 0x03, 0x06, 0x01, 0x11, 0x3F, 0x3B
ERR = CtapError.ERR


def cdh() -> bytes:
    return os.urandom(32)


def sha(s: str) -> bytes:
    return hashlib.sha256(s.encode()).digest()


def rand_rp(tag: str) -> dict:
    return {"id": f"{tag}-{os.urandom(4).hex()}.test", "name": tag}


# ---- board access ----

def http(path: str, method="GET"):
    req = urllib.request.Request(DEVICE + path, method=method, data=b"{}" if method == "POST" else None,
                                 headers={"Origin": DEVICE, "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=5) as r:
        return json.loads(r.read() or b"null")


def status() -> dict:
    return http("/api/status")


def find_hid(timeout=30.0):
    end = time.time() + timeout
    while time.time() < end:
        for d in CtapHidDevice.list_devices():
            if d.descriptor.vid == VID and d.descriptor.pid == PID:
                return d
        time.sleep(0.5)
    raise AssertionError("FIDO HID device not found")


def reboot_board() -> float:
    """Normal reboot via the API. Returns the time the new firmware answered (its uptime starts near it)."""
    http("/api/reboot?mode=normal", "POST")
    time.sleep(2)
    end = time.time() + 40
    while time.time() < end:
        try:
            st = status()
            if st.get("uptime_s", 99) < 30:
                return time.time() - st["uptime_s"]
        except OSError:
            pass
        time.sleep(0.3)
    raise AssertionError("board did not come back after reboot")


class Board:
    """Ctap2 / Ctap1 handles that survive a board reboot (reconnect)."""

    def __init__(self):
        self.connect()

    def connect(self):
        """(Re)opens the HID device. Also used between checks: on some hosts every open handle receives
        every IN report, so raw-channel traffic would otherwise sit in this handle's queue."""
        if getattr(self, "dev", None) is not None:
            try:
                self.dev.close()
            except Exception:
                pass
        self.dev = find_hid()
        self.ctap = Ctap2(self.dev)
        self.u2f = Ctap1(self.dev)

    def raw_cbor(self, cmd: int, payload: bytes = b"") -> bytes:
        return self.dev.call(CBOR_CMD, bytes([cmd]) + payload)


class RawHid:
    """CTAPHID packets with timed reads, portable across python-fido2 backends: a reader thread
    blocks in read_packet() and feeds a queue."""

    def __init__(self, desc):
        self.conn = open_connection(desc)
        self.q = queue.Queue()
        self.closed = False
        threading.Thread(target=self._reader, daemon=True).start()

    def _reader(self):
        while not self.closed:
            try:
                self.q.put(bytes(self.conn.read_packet()))
            except OSError:
                time.sleep(0.05)

    def close(self):
        self.closed = True
        self.conn.close()

    def raw(self, pkt: bytes):
        self.conn.write_packet(pkt.ljust(64, b"\0"))

    def rd(self, t=1.0):
        try:
            return self.q.get(timeout=max(t, 0.001))
        except queue.Empty:
            return None

    def drain(self, t=0.3):
        while self.rd(t) is not None:
            pass

    def send(self, cid, cmd, data=b"", bcnt=None):
        n = len(data) if bcnt is None else bcnt
        self.raw(struct.pack(">IBH", cid, 0x80 | cmd, n) + data[:57])
        off, seq = 57, 0
        while off < len(data):
            self.raw(struct.pack(">IB", cid, seq) + data[off:off + 59])
            off += 59
            seq += 1

    def recv(self, cid, t=2.0, keepalives=None):
        """(cmd, data) of the next message on cid, or None. KEEPALIVEs are counted into keepalives."""
        end = time.time() + t
        while time.time() < end:
            p = self.rd(end - time.time())
            if p is None:
                break
            pcid, cmd = struct.unpack(">IB", p[:5])
            if pcid != cid or not cmd & 0x80:
                continue
            cmd &= 0x7F
            n = struct.unpack(">H", p[5:7])[0]
            if cmd == KEEPALIVE_CMD:
                if keepalives is not None:
                    keepalives.append(p[7])
                continue
            data, seq = p[7:7 + n], 0
            while len(data) < n:
                q = self.rd(1.0)
                if q is None or q[4] != seq:
                    raise AssertionError("broken continuation sequence")
                data += q[5:5 + n - len(data)]
                seq += 1
            return cmd, data
        return None

    def alloc(self) -> int:
        nonce = os.urandom(8)
        self.send(BCAST, INIT_CMD, nonce)
        end = time.time() + 2
        while time.time() < end:   # INIT replies to other handles' allocations may be queued too
            r = self.recv(BCAST, end - time.time())
            if r and r[0] == INIT_CMD and r[1][:8] == nonce:
                return struct.unpack(">I", r[1][8:12])[0]
        raise AssertionError("INIT on broadcast got no reply")


# ---- helpers ----

def expect_err(code, fn, what):
    try:
        fn()
    except CtapError as e:
        if e.code != code:
            raise AssertionError(f"{what}: got {e.code!r}, expected {code!r}") from e
        return
    raise AssertionError(f"{what}: succeeded, expected {code!r}")


def make_cred(b: Board, rp, user=None, rk=False, ext=None, c=None):
    user = user or {"id": os.urandom(8), "name": "n", "displayName": "d"}
    return b.ctap.make_credential(c or cdh(), rp, user, ES256_PARAMS, options={"rk": True} if rk else None,
                                  extensions=ext)


def mc_bytes(over=None, rp_id="mc.test") -> bytes:
    """makeCredential request; over replaces or (with None) removes members."""
    req = {1: cdh(), 2: {"id": rp_id, "name": "x"}, 3: {"id": b"u", "name": "n"}, 4: ES256_PARAMS}
    req.update(over or {})
    return cbor.encode({k: v for k, v in req.items() if v is not None})


def ga_bytes(over=None, rp_id="ga.test") -> bytes:
    req = {1: rp_id, 2: cdh()}
    req.update(over or {})
    return cbor.encode({k: v for k, v in req.items() if v is not None})


def u2f_register(b: Board, app: bytes, client: bytes, p1=0):
    """REGISTER with a retry on 6985 (CONDITIONS_NOT_SATISFIED), like a browser polls."""
    end = time.time() + 30
    while True:
        try:
            resp = b.u2f.send_apdu(ins=Ctap1.INS.REGISTER, p1=p1, data=client + app)
            from fido2.ctap1 import RegistrationData
            return RegistrationData(resp)
        except ApduError as e:
            if e.code != 0x6985 or time.time() > end:
                raise
            time.sleep(0.1)


def u2f_auth_raw(b: Board, p1, app, client, kh) -> bytes:
    return b.u2f.send_apdu(ins=Ctap1.INS.AUTHENTICATE, p1=p1, data=client + app + bytes([len(kh)]) + kh)


def u2f_auth(b: Board, app, client, kh, p1=0x03):
    end = time.time() + 30
    while True:
        try:
            return u2f_auth_raw(b, p1, app, client, kh)
        except ApduError as e:
            if e.code != 0x6985 or time.time() > end:
                raise
            time.sleep(0.1)


def ga_counter(b: Board, rp_id, cred_id, up=True):
    r = b.ctap.get_assertion(rp_id, cdh(), [{"type": "public-key", "id": cred_id}],
                             options=None if up else {"up": False})
    return r.auth_data.counter, r.auth_data.flags


# ---- checks that need presence (test build) ----

def check_get_info(b: Board):
    info = b.ctap.get_info()
    raw = b.raw_cbor(0x04)
    if raw[0] != 0 or cbor.encode(cbor.decode(raw[1:])) != raw[1:]:
        raise AssertionError("getInfo is not canonical CBOR")
    if info.versions != ["U2F_V2", "FIDO_2_0", "FIDO_2_1"]:
        raise AssertionError(f"versions {info.versions}")
    want = {"rk": True, "up": True, "plat": False, "credMgmt": True, "clientPin": info.options.get("clientPin"),
            "pinUvAuthToken": True, "makeCredUvNotRqd": True}
    if info.options != want or not isinstance(want["clientPin"], bool):
        raise AssertionError(f"options {info.options}, expected {want}")
    if info.extensions != ["credProtect", "hmac-secret"] or info.min_pin_length != 4 or \
            info.transports != ["usb"] or info.algorithms != [{"alg": -7, "type": "public-key"}]:
        raise AssertionError(f"getInfo: {info}")
    if info.aaguid != AAGUID:
        raise AssertionError(f"aaguid {info.aaguid}")
    if info.max_creds_in_list != 8 or info.max_cred_id_length != 48:
        raise AssertionError(f"getInfo 7/8: {info.max_creds_in_list} {info.max_cred_id_length}")
    if info.pin_uv_protocols != [2, 1]:
        raise AssertionError(f"extensions {info.extensions} protocols {info.pin_uv_protocols}")
    print(f"   versions {info.versions} options {info.options}")


def check_reset_outside_window(b: Board):
    expect_err(ERR.NOT_ALLOWED, b.ctap.reset, "reset after 10 s")


def check_packed_self_attestation(b: Board):
    c = cdh()
    reg = make_cred(b, rand_rp("att"), c=c)
    if reg.fmt != "packed" or "x5c" in reg.att_stmt or reg.att_stmt.get("alg") != -7:
        raise AssertionError(f"packed self attestation expected, got {reg.fmt} {list(reg.att_stmt)}")
    res = PackedAttestation().verify(reg.att_stmt, reg.auth_data, c)
    if res.attestation_type != AttestationType.SELF:
        raise AssertionError(f"attestation type {res.attestation_type}")
    if reg.auth_data.credential_data.aaguid != AAGUID or reg.auth_data.counter != 0:
        raise AssertionError("aaguid or signCount wrong in makeCredential authData")


def check_u2f_attestation(b: Board):
    app, client = sha("https://u2f-att.test"), cdh()
    r1 = u2f_register(b, app, client, p1=0)          # P1=0, as python-fido2 / libfido2 send it
    r2 = u2f_register(b, app, cdh(), p1=3)           # P1=3, as Chrome sends it
    for r, cp in ((r1, client),):
        FidoU2FAttestation.verify_signature(app, cp, r.key_handle, r.public_key, r.certificate, r.signature)
    r1.verify(app, client)
    if r1.certificate != r2.certificate:
        raise AssertionError("U2F certificate differs between registrations (must be the fixed batch cert)")
    cert = x509.load_der_x509_certificate(r1.certificate)
    cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    if "batch" not in cn or bc.ca:
        raise AssertionError(f"unexpected U2F cert subject {cert.subject.rfc4514_string()}")
    print(f"   U2F cert: {cert.subject.rfc4514_string()}")


def check_cross_protocol(b: Board):
    rp_id = f"cross-{os.urandom(3).hex()}.test"
    app = sha(rp_id)
    # U2F register -> CTAP2 getAssertion with that key handle.
    reg = u2f_register(b, app, cdh())
    c = cdh()
    a = b.ctap.get_assertion(rp_id, c, [{"type": "public-key", "id": reg.key_handle}])
    a.verify(c, ES256.from_ctap1(reg.public_key))
    # CTAP2 makeCredential -> U2F authenticate with appParam = SHA-256(rpId).
    mc = make_cred(b, {"id": rp_id, "name": "x"})
    cd = mc.auth_data.credential_data
    client = cdh()
    resp = u2f_auth(b, app, client, cd.credential_id)
    sig_base = app + resp[:5] + client
    cd.public_key.verify(sig_base, resp[5:])
    # Wrong appParam: not ours.
    try:
        u2f_auth_raw(b, 0x03, sha("other.test"), client, cd.credential_id)
        raise AssertionError("U2F authenticate with a foreign appParam succeeded")
    except ApduError as e:
        if e.code != 0x6A80:
            raise AssertionError(f"foreign appParam: {e.code:#x}, expected 6a80")


def check_u2f_modes(b: Board):
    app = sha("u2f-modes.test")
    reg = u2f_register(b, app, cdh())
    kh = reg.key_handle
    try:
        u2f_auth_raw(b, 0x07, app, cdh(), kh)
        raise AssertionError("check-only returned success")
    except ApduError as e:
        if e.code != 0x6985:
            raise AssertionError(f"check-only on own handle: {e.code:#x}, expected 6985")
    try:
        u2f_auth_raw(b, 0x07, sha("x.test"), cdh(), kh)
        raise AssertionError("check-only on a foreign app returned success")
    except ApduError as e:
        if e.code != 0x6A80:
            raise AssertionError(f"check-only foreign: {e.code:#x}, expected 6a80")
    e1 = u2f_auth(b, app, cdh(), kh)
    dn = u2f_auth_raw(b, 0x08, app, cdh(), kh)            # dont-enforce: no presence, no counter step
    e2 = u2f_auth(b, app, cdh(), kh)
    c1, cn, c2 = (struct.unpack(">I", r[1:5])[0] for r in (e1, dn, e2))
    if not e1[0] & 1 or dn[0] & 1 or not e2[0] & 1:
        raise AssertionError(f"UP bits: enforce {e1[0]}, dont-enforce {dn[0]}, enforce {e2[0]}")
    if not (cn == c1 and c2 > c1):
        raise AssertionError(f"counters enforce {c1}, dont-enforce {cn}, enforce {c2}")
    print(f"   counters {c1} -> (no-UP) {cn} -> {c2}")


def check_up_false(b: Board):
    rp = rand_rp("upf")
    cid = make_cred(b, rp).auth_data.credential_data.credential_id
    c1, f1 = ga_counter(b, rp["id"], cid)
    c2, f2 = ga_counter(b, rp["id"], cid, up=False)
    c3, f3 = ga_counter(b, rp["id"], cid)
    if not f1 & FLAG_UP or f2 & FLAG_UP or not f3 & FLAG_UP:
        raise AssertionError(f"UP flags {f1:#x} {f2:#x} {f3:#x}")
    if not (c2 == c1 and c3 > c1):
        raise AssertionError(f"counters {c1} (up) {c2} (up:false) {c3} (up)")
    expect_err(ERR.INVALID_OPTION, lambda: b.ctap.make_credential(cdh(), rp, {"id": b"u"}, ES256_PARAMS,
                                                                   options={"up": False}), "makeCredential up:false")
    print(f"   counters {c1} -> (up:false) {c2} -> {c3}")


def check_allowlist_no_fallback(b: Board):
    rp = rand_rp("nofb")
    make_cred(b, rp, rk=True)
    other = make_cred(b, rand_rp("nofb-other")).auth_data.credential_data.credential_id
    for allow in ([{"type": "public-key", "id": os.urandom(48)}], [{"type": "public-key", "id": other}]):
        expect_err(ERR.NO_CREDENTIALS, lambda: b.ctap.get_assertion(rp["id"], cdh(), allow),
                   "allowList without a match, resident present")
    # Empty allowList counts as absent: the resident is used.
    st = b.raw_cbor(0x02, ga_bytes({3: []}, rp["id"]))
    if st[0] != 0:
        raise AssertionError(f"empty allowList: status {st[0]:#x}, expected the resident")


def check_rk_overwrite_and_user(b: Board):
    rp = rand_rp("rkow")
    uid = os.urandom(16)
    make_cred(b, rp, {"id": uid, "name": "alice", "displayName": "Alice"}, rk=True)
    second = make_cred(b, rp, {"id": uid, "name": "alice2", "displayName": "Alice 2"}, rk=True)
    a = b.ctap.get_assertion(rp["id"], cdh())
    if a.number_of_credentials not in (None, 1):
        raise AssertionError(f"same user id twice: {a.number_of_credentials} credentials, expected 1")
    if a.credential["id"] != second.auth_data.credential_data.credential_id:
        raise AssertionError("resident was not overwritten by the newer credential")
    if dict(a.user) != {"id": uid}:
        raise AssertionError(f"user entity without UV must be id only, got {a.user}")


def check_next_assertion(b: Board):
    rp = rand_rp("next")
    older = make_cred(b, rp, {"id": b"older", "name": "o"}, rk=True)
    newer = make_cred(b, rp, {"id": b"newer", "name": "n"}, rk=True)
    first = b.ctap.get_assertion(rp["id"], cdh())
    if first.number_of_credentials != 2 or first.user["id"] != b"newer":
        raise AssertionError(f"first: {first.number_of_credentials} {first.user}")
    second = b.ctap.get_next_assertion()
    if second.user["id"] != b"older":
        raise AssertionError("second assertion is not the older resident")
    expect_err(ERR.NOT_ALLOWED, b.ctap.get_next_assertion, "getNextAssertion after the list")
    # Any other command drops the list.
    b.ctap.get_assertion(rp["id"], cdh())
    b.ctap.get_info()
    expect_err(ERR.NOT_ALLOWED, b.ctap.get_next_assertion, "getNextAssertion after another command")
    del older, newer
    # The pending list expires 30 s after the last step.
    b.ctap.get_assertion(rp["id"], cdh())
    time.sleep(31)
    expect_err(ERR.NOT_ALLOWED, b.ctap.get_next_assertion, "getNextAssertion after 31 s")


def check_key_store_full(b: Board):
    """Fills the 16 resident slots: the next new user gets KEY_STORE_FULL, an existing user can still be
    overwritten. Leaves the store full, so it runs after every other resident-creating check."""
    rp = rand_rp("full")
    made = 0
    for i in range(17):
        try:
            make_cred(b, rp, {"id": b"full%d" % i, "name": "f"}, rk=True)
            made += 1
        except CtapError as e:
            if e.code != ERR.KEY_STORE_FULL:
                raise
            break
    else:
        raise AssertionError("17 new residents accepted")
    make_cred(b, rp, {"id": b"full0", "name": "again"}, rk=True)
    make_cred(b, rand_rp("full-nonrk"))   # non-resident credentials need no slot
    print(f"   {made} new residents fitted, then KEY_STORE_FULL; overwrite still ok")


def check_cancel_then_retry_auto(b: Board, h: RawHid):
    """Test build: CANCEL while idle, and a CANCEL that arrives after the reply, must not poison the next request."""
    cid = h.alloc()
    h.send(cid, CANCEL_CMD)
    h.send(cid, CBOR_CMD, b"\x01" + mc_bytes())
    r = h.recv(cid, 5)
    if not r or r[0] != CBOR_CMD or r[1][0] != 0:
        raise AssertionError(f"makeCredential after an idle CANCEL: {r}")
    h.send(cid, CANCEL_CMD)
    h.send(cid, CBOR_CMD, b"\x01" + mc_bytes())
    r = h.recv(cid, 5)
    if not r or r[1][0] != 0:
        raise AssertionError(f"makeCredential after a late CANCEL: {r}")


def nested(depth_arrays: int) -> bytes:
    return b"\x81" * depth_arrays + b"\x00"


def check_cbor_limits(b: Board):
    # Root map (1) + extensions map (2) + n arrays: depth 8 is the limit.
    base = ga_bytes(rp_id="nest.test")
    def with_ext(inner: bytes) -> bytes:
        body = base[1:]   # drop the map(2) head, append key 4 (extensions)
        return bytes([0xA3]) + body + b"\x04\xa1\x62zz" + inner
    ok = b.raw_cbor(0x02, with_ext(nested(6)))
    bad = b.raw_cbor(0x02, with_ext(nested(7)))
    huge = b.raw_cbor(0x02, with_ext(nested(2000)))
    items = b.raw_cbor(0x02, with_ext(b"\x99\x02\x58" + b"\x00" * 600))
    if ok[0] != ERR.NO_CREDENTIALS or bad[0] != ERR.INVALID_CBOR or huge[0] != ERR.INVALID_CBOR or \
            items[0] != ERR.INVALID_CBOR:
        raise AssertionError(f"depth 8 {ok[0]:#x}, depth 9 {bad[0]:#x}, depth 2002 {huge[0]:#x}, 600 items {items[0]:#x}")
    b.ctap.get_info()   # still alive


def error_table(b: Board):
    """(name, cmd, payload, expected status) for requests that fail before any presence check."""
    ka = {"type": "public-key", "id": os.urandom(48)}
    c = cdh()
    rows = [
        ("GA missing rpId", 2, cbor.encode({2: c}), ERR.MISSING_PARAMETER),
        ("GA missing cdh", 2, cbor.encode({1: "a.test"}), ERR.MISSING_PARAMETER),
        ("GA rpId as bytes", 2, cbor.encode({1: b"a", 2: c}), ERR.CBOR_UNEXPECTED_TYPE),
        ("GA cdh as text", 2, cbor.encode({1: "a.test", 2: "x"}), ERR.CBOR_UNEXPECTED_TYPE),
        ("GA cdh 31 bytes", 2, cbor.encode({1: "a.test", 2: c[:31]}), ERR.INVALID_PARAMETER),
        ("GA allowList not array", 2, ga_bytes({3: 5}), ERR.CBOR_UNEXPECTED_TYPE),
        ("GA allowList entry no type", 2, ga_bytes({3: [{"id": b"x"}]}), ERR.CBOR_UNEXPECTED_TYPE),
        ("GA options not map", 2, ga_bytes({5: 1}), ERR.CBOR_UNEXPECTED_TYPE),
        ("GA up as int", 2, ga_bytes({5: {"up": 1}}), ERR.CBOR_UNEXPECTED_TYPE),
        ("GA rk option", 2, ga_bytes({3: [ka], 5: {"rk": True}}), ERR.UNSUPPORTED_OPTION),
        ("GA uv:true", 2, ga_bytes({3: [ka], 5: {"uv": True}}), ERR.INVALID_OPTION),
        ("GA no credentials", 2, ga_bytes({3: [ka]}), ERR.NO_CREDENTIALS),
        ("GA pinAuth 16 bytes", 2, ga_bytes({6: b"\0" * 16, 7: 1}), ERR.PIN_NOT_SET),
        ("GA trailing byte", 2, ga_bytes() + b"\x00", ERR.INVALID_CBOR),
        ("GA duplicate key", 2, b"\xa3\x01\x66a.test\x01\x66a.test\x02\x58\x20" + c, ERR.INVALID_CBOR),
        ("GA key order 2,1", 2, b"\xa2\x02\x58\x20" + c + b"\x01\x66a.test", ERR.INVALID_CBOR),
        ("GA non-minimal key", 2, b"\xa2\x18\x01\x66a.test\x02\x58\x20" + c, ERR.INVALID_CBOR),
        ("GA tag on rpId", 2, b"\xa2\x01\xc0\x66a.test\x02\x58\x20" + c, ERR.INVALID_CBOR),
        ("GA indefinite map", 2, b"\xbf\x01\x66a.test\x02\x58\x20" + c + b"\xff", ERR.INVALID_CBOR),
        ("GA root is array", 2, b"\x82\x01\x02", ERR.INVALID_CBOR),
        ("GA truncated", 2, ga_bytes()[:-3], ERR.INVALID_CBOR),
        ("MC missing cdh", 1, mc_bytes({1: None}), ERR.MISSING_PARAMETER),
        ("MC cdh as text", 1, mc_bytes({1: "x"}), ERR.CBOR_UNEXPECTED_TYPE),
        ("MC missing rp", 1, mc_bytes({2: None}), ERR.MISSING_PARAMETER),
        ("MC rp not map", 1, mc_bytes({2: "a.test"}), ERR.CBOR_UNEXPECTED_TYPE),
        ("MC rp without id", 1, mc_bytes({2: {"name": "x"}}), ERR.CBOR_UNEXPECTED_TYPE),
        ("MC missing user", 1, mc_bytes({3: None}), ERR.MISSING_PARAMETER),
        ("MC user.id missing", 1, mc_bytes({3: {"name": "n"}}), ERR.CBOR_UNEXPECTED_TYPE),
        ("MC user.id 65 bytes", 1, mc_bytes({3: {"id": b"u" * 65}}), ERR.INVALID_PARAMETER),
        ("MC user.name as int", 1, mc_bytes({3: {"id": b"u", "name": 5}}), ERR.CBOR_UNEXPECTED_TYPE),
        ("MC missing params", 1, mc_bytes({4: None}), ERR.MISSING_PARAMETER),
        ("MC params not array", 1, mc_bytes({4: {}}), ERR.CBOR_UNEXPECTED_TYPE),
        ("MC params entry not map", 1, mc_bytes({4: [1]}), ERR.CBOR_UNEXPECTED_TYPE),
        ("MC params alg as text", 1, mc_bytes({4: [{"type": "public-key", "alg": "x"}]}), ERR.CBOR_UNEXPECTED_TYPE),
        ("MC params RS256 only", 1, mc_bytes({4: [{"type": "public-key", "alg": -257}]}), ERR.UNSUPPORTED_ALGORITHM),
        ("MC options not map", 1, mc_bytes({7: []}), ERR.CBOR_UNEXPECTED_TYPE),
        ("MC uv:true", 1, mc_bytes({7: {"uv": True}}), ERR.INVALID_OPTION),
        ("MC up:false", 1, mc_bytes({7: {"up": False}}), ERR.INVALID_OPTION),
        ("MC excludeList not array", 1, mc_bytes({5: {}}), ERR.CBOR_UNEXPECTED_TYPE),
        ("MC pinAuth 16 bytes", 1, mc_bytes({8: b"\0" * 16, 9: 1}), ERR.PIN_NOT_SET),
        ("getInfo trailing byte", 4, b"\x00", ERR.INVALID_LENGTH),
        ("getNextAssertion, nothing pending", 8, b"", ERR.NOT_ALLOWED),
        ("unknown command 0x40", 0x40, b"", ERR.INVALID_COMMAND),
        ("clientPin missing protocol", 6, cbor.encode({2: 2}), ERR.MISSING_PARAMETER),
        ("clientPin protocol 3", 6, cbor.encode({1: 3, 2: 2}), ERR.INVALID_PARAMETER),
        ("clientPin subcommand as text", 6, cbor.encode({1: 1, 2: "x"}), ERR.CBOR_UNEXPECTED_TYPE),
        ("clientPin getUVRetries (no built-in UV)", 6, cbor.encode({1: 1, 2: 7}), ERR.INVALID_SUBCOMMAND),
        ("clientPin getPinToken, no PIN", 6, cbor.encode({1: 1, 2: 5, 3: {1: 2}, 6: b"\0" * 16}), ERR.PIN_NOT_SET),
        ("credMgmt missing subcommand", 0x0A, cbor.encode({3: 1}), ERR.MISSING_PARAMETER),
        ("credMgmt subcommand 9", 0x0A, cbor.encode({1: 9}), ERR.INVALID_SUBCOMMAND),
        ("credMgmt metadata, no pinUvAuthParam", 0x0A, cbor.encode({1: 1}), ERR.PUAT_REQUIRED),
        ("credMgmt metadata, no protocol", 0x0A, cbor.encode({1: 1, 4: b"\0" * 32}), ERR.MISSING_PARAMETER),
        ("credMgmt metadata, no token", 0x0A, cbor.encode({1: 1, 3: 2, 4: b"\0" * 32}), ERR.PIN_AUTH_INVALID),
        ("credMgmt next RP, nothing begun", 0x0A, cbor.encode({1: 3}), ERR.NOT_ALLOWED),
        ("selection with a payload", 0x0B, b"\xa0", ERR.INVALID_LENGTH),
    ]
    return rows


def check_error_table(b: Board):
    bad = []
    for name, cmd, payload, want in error_table(b):
        got = b.raw_cbor(cmd, payload)[0]
        if got != want:
            bad.append(f"{name}: {got:#04x}, expected {int(want):#04x}")
    if bad:
        raise AssertionError("; ".join(bad))
    print(f"   {len(error_table(b))} rows")


def check_zero_len_pin_auth(b: Board):
    """Zero-length pinUvAuthParam: presence first, then PIN_NOT_SET (no PIN set)."""
    for cmd, payload in ((1, mc_bytes({8: b"", 9: 1})), (2, ga_bytes({6: b"", 7: 1}))):
        st = b.raw_cbor(cmd, payload)[0]
        if st != ERR.PIN_NOT_SET:
            raise AssertionError(f"cmd {cmd} zero-length pinUvAuthParam: {st:#x}")


def check_hid_channels(b: Board, h: RawHid):
    cid = h.alloc()
    cid2 = h.alloc()
    if cid in (0, BCAST) or cid2 == cid or abs(cid2 - cid) < 16:
        raise AssertionError(f"CIDs look sequential: {cid:#x} {cid2:#x}")
    results = {}
    for name, c in (("CID 0", 0), ("unallocated CID", 0x12345678 if cid != 0x12345678 else 0x23456789)):
        h.send(c, PING_CMD, b"hi")
        results[name] = h.recv(c)
    h.send(BCAST, PING_CMD, b"hi")
    results["PING on broadcast"] = h.recv(BCAST)
    h.send(BCAST, INIT_CMD, os.urandom(7))
    results["INIT bcnt 7"] = h.recv(BCAST)
    h.send(cid, 0x09)
    results["unknown cmd 0x09"] = h.recv(cid)
    h.send(cid, 0x08)
    results["WINK (not in caps)"] = h.recv(cid)
    want = {"CID 0": 0x0B, "unallocated CID": 0x0B, "PING on broadcast": 0x0B, "INIT bcnt 7": 0x03,
            "unknown cmd 0x09": 0x01, "WINK (not in caps)": 0x01}
    bad = [f"{k}: {results[k]}" for k, v in want.items()
           if not results[k] or results[k][0] != ERROR_CMD or results[k][1][:1] != bytes([v])]
    if bad:
        raise AssertionError("; ".join(bad))
    # Both allocated channels still work.
    for c in (cid, cid2):
        h.send(c, PING_CMD, b"ok")
        if h.recv(c) != (PING_CMD, b"ok"):
            raise AssertionError(f"PING on allocated CID {c:#x} failed")


def check_init_resync(b: Board, h: RawHid):
    cid = h.alloc()
    data = os.urandom(100)
    h.send(cid, PING_CMD, data[:57], bcnt=100)     # first packet only: assembly in progress
    nonce = os.urandom(8)
    h.send(cid, INIT_CMD, nonce)
    r = h.recv(cid)
    if not r or r[0] != INIT_CMD or r[1][:8] != nonce or struct.unpack(">I", r[1][8:12])[0] != cid:
        raise AssertionError(f"INIT on own CID mid-assembly: {r}")
    h.raw(struct.pack(">IB", cid, 0) + data[57:])   # stale continuation: ignored
    if h.recv(cid, 0.5) is not None:
        raise AssertionError("stale continuation after INIT produced a reply")
    h.send(cid, PING_CMD, b"after")
    if h.recv(cid) != (PING_CMD, b"after"):
        raise AssertionError("PING after resync failed")


# ---- hmac-secret (kept from the earlier suite) ----

def hs_input(ctap, proto, salts, tamper=False, omit_proto=False, bad_point=False):
    key_agreement, shared = ClientPin(ctap, proto)._get_shared_secret()
    salt_enc = proto.encrypt(shared, b"".join(salts))
    salt_auth = proto.authenticate(shared, salt_enc)
    if tamper:
        salt_auth = bytes([salt_auth[0] ^ 1]) + salt_auth[1:]
    if bad_point:
        key_agreement = dict(key_agreement)
        y = bytearray(key_agreement[-3])
        y[31] ^= 1
        key_agreement[-3] = bytes(y)
    hs = {1: key_agreement, 2: salt_enc, 3: salt_auth}
    if not omit_proto:
        hs[4] = proto.VERSION
    return {"hmac-secret": hs}, shared


def hs_outputs(proto, shared, resp, nsalt):
    ad = resp.auth_data
    if not ad.flags & FLAG_ED:
        raise AssertionError(f"getAssertion: ED flag missing (flags {ad.flags:#x})")
    plain = proto.decrypt(shared, ad.extensions["hmac-secret"])
    if len(plain) != 32 * nsalt:
        raise AssertionError(f"hmac-secret output is {len(plain)} bytes, expected {32 * nsalt}")
    return [plain[i:i + 32] for i in range(0, len(plain), 32)]


def hs_assert(ctap, proto, rp_id, cred_id, salts, pub=None, **kw):
    ext, shared = hs_input(ctap, proto, salts, **kw)
    allow = [{"type": "public-key", "id": cred_id}] if cred_id else None
    c = cdh()
    resp = ctap.get_assertion(rp_id, c, allow, ext)
    if pub is not None:
        resp.verify(c, pub)
    return hs_outputs(proto, shared, resp, len(salts))


def hs_via_client_ext(ctap, proto, rp_id, cred_id, s1, s2):
    desc = PublicKeyCredentialDescriptor(type="public-key", id=cred_id)
    opts = PublicKeyCredentialRequestOptions(challenge=os.urandom(32), rp_id=rp_id, allow_credentials=[desc],
                                             extensions={"hmacGetSecret": {"salt1": s1, "salt2": s2}})
    proc = HmacSecretExtension(allow_hmac_secret=True).get_assertion(ctap, opts, proto)
    inputs = proc.prepare_inputs(desc, None)
    resp = ctap.get_assertion(rp_id, cdh(), [{"type": "public-key", "id": cred_id}], inputs)
    out = proc.prepare_outputs(resp, None)["hmacGetSecret"]
    return out.output1, out.output2


def make_hmac_cred(b: Board, rp, rk=False):
    reg = make_cred(b, rp, rk=rk, ext={"hmac-secret": True})
    ad = reg.auth_data
    if not ad.flags & FLAG_ED or ad.extensions != {"hmac-secret": True}:
        raise AssertionError(f"makeCredential: ED/extensions wrong: flags {ad.flags:#x} ext {ad.extensions}")
    return ad.credential_data.credential_id, ad.credential_data.public_key


def check_hmac_secret(b: Board):
    ctap = b.ctap
    rp = rand_rp("hmac")
    rid = rp["id"]
    c1, pub1 = make_hmac_cred(b, rp)
    c2, _ = make_hmac_cred(b, rp)
    s1, s2 = os.urandom(32), os.urandom(32)
    per_proto = {}
    for proto in (PinProtocolV1(), PinProtocolV2()):
        v = proto.VERSION
        (o1,) = hs_assert(ctap, proto, rid, c1, [s1], pub1)
        (o1b,) = hs_assert(ctap, proto, rid, c1, [s1], pub1)
        t1, t2 = hs_assert(ctap, proto, rid, c1, [s1, s2], pub1)
        (p1,) = hs_assert(ctap, proto, rid, c2, [s1])
        e1, e2 = hs_via_client_ext(ctap, proto, rid, c1, s1, s2)
        if o1 != o1b or t1 != o1 or t2 == o1 or p1 == o1 or (e1, e2) != (t1, t2):
            raise AssertionError(f"v{v}: hmac-secret outputs inconsistent")
        expect_err(ERR.PIN_AUTH_INVALID, lambda: hs_assert(ctap, proto, rid, c1, [s1], tamper=True),
                   f"v{v} tampered saltAuth")
        expect_err(ERR.INVALID_PARAMETER, lambda: hs_assert(ctap, proto, rid, c1, [s1], bad_point=True),
                   f"v{v} off-curve platform key")
        per_proto[v] = o1
    if per_proto[1] != per_proto[2]:
        raise AssertionError("v1 and v2 disagree on the output for the same credential and salt")
    p1 = PinProtocolV1()
    (n1,) = hs_assert(ctap, p1, rid, c1, [s1], omit_proto=True)
    if n1 != per_proto[1]:
        raise AssertionError("v1 without pinUvAuthProtocol gave a different output")
    allow = [{"type": "public-key", "id": c1}]
    ext, _ = hs_input(ctap, p1, [s1])
    for bad, code, what in (({**ext["hmac-secret"], 2: b"\0" * 48}, ERR.INVALID_PARAMETER, "saltEnc 48 bytes"),
                            ({**ext["hmac-secret"], 4: 3}, ERR.INVALID_PARAMETER, "pinUvAuthProtocol 3"),
                            ({k: x for k, x in ext["hmac-secret"].items() if k != 3}, ERR.MISSING_PARAMETER,
                             "saltAuth missing")):
        expect_err(code, lambda: ctap.get_assertion(rid, cdh(), allow, {"hmac-secret": bad}), what)
    expect_err(ERR.UNSUPPORTED_OPTION, lambda: ctap.get_assertion(rid, cdh(), allow, ext, {"up": False}),
               "hmac-secret with up=false")
    rk_rp = rand_rp("hmacrk")
    r_old, _ = make_hmac_cred(b, rk_rp, rk=True)
    r_new, _ = make_hmac_cred(b, rk_rp, rk=True)
    for proto in (p1, PinProtocolV2()):
        ext, shared = hs_input(ctap, proto, [s1, s2])
        first = ctap.get_assertion(rk_rp["id"], cdh(), None, ext)
        second = ctap.get_next_assertion()
        f_out = hs_outputs(proto, shared, first, 2)
        s_out = hs_outputs(proto, shared, second, 2)
        if first.credential["id"] != r_new or second.credential["id"] != r_old:
            raise AssertionError("resident order wrong")
        if f_out != hs_assert(ctap, proto, rk_rp["id"], r_new, [s1, s2]) or \
                s_out != hs_assert(ctap, proto, rk_rp["id"], r_old, [s1, s2]) or f_out == s_out:
            raise AssertionError(f"v{proto.VERSION}: getNextAssertion hmac-secret outputs wrong")
    return rid, c1, s1, per_proto[1], pub1


# ---- clientPIN, pinUvAuthToken, credProtect, credentialManagement (CTAP 2.1) ----

PIN, PIN2 = "4711-sentinel", "0815-sentinel"
PERM = ClientPin.PERMISSION
FLAG_UV = 0x04


def cpin(b: Board, proto=None) -> ClientPin:
    return ClientPin(b.ctap, proto or PinProtocolV2())


def pin_token(b: Board, pin=PIN, perms=None, rpid=None, proto=None):
    proto = proto or PinProtocolV2()
    return proto, cpin(b, proto).get_pin_token(pin, perms, rpid)


def retries(b: Board):
    r = cbor.decode(b.raw_cbor(6, cbor.encode({2: 1}))[1:])   # getPINRetries needs no protocol
    return r[3], r[4]


def mc_uv(b: Board, rp, proto, tok, rk=False, ext=None, user=None, exclude=None, options=None):
    c = cdh()
    opts = dict(options or {})
    if rk:
        opts["rk"] = True
    return b.ctap.make_credential(c, rp, user or {"id": os.urandom(8), "name": "n", "displayName": "d"},
                                  ES256_PARAMS, exclude_list=exclude, extensions=ext, options=opts or None,
                                  pin_uv_param=proto.authenticate(tok, c), pin_uv_protocol=proto.VERSION)


def ga_uv(b: Board, rp_id, proto, tok, allow=None, ext=None, c=None):
    c = c or cdh()
    return b.ctap.get_assertion(rp_id, c, allow, ext, pin_uv_param=proto.authenticate(tok, c),
                                pin_uv_protocol=proto.VERSION)


def setpin_raw(b: Board, proto, padded: bytes):
    ka, ss = cpin(b, proto)._get_shared_secret()
    enc = proto.encrypt(ss, padded)
    b.ctap.client_pin(proto.VERSION, ClientPin.CMD.SET_PIN, key_agreement=ka, new_pin_enc=enc,
                      pin_uv_param=proto.authenticate(ss, enc))


def token_raw(b: Board, proto, pin_hash_plain: bytes):
    ka, ss = cpin(b, proto)._get_shared_secret()
    b.ctap.client_pin(proto.VERSION, ClientPin.CMD.GET_TOKEN_USING_PIN_LEGACY, key_agreement=ka,
                      pin_hash_enc=proto.encrypt(ss, pin_hash_plain))


def check_set_pin(b: Board):
    if retries(b) != (8, False):
        raise AssertionError(f"getPINRetries before setPIN: {retries(b)}")
    up0 = status()["uptime_s"]
    v1, v2 = PinProtocolV1(), PinProtocolV2()
    for pin, what in (("123", "3 characters"), ("ééé", "3 code points in 6 bytes"),
                      ("x" * 64, "64 bytes")):
        padded = pin.encode().ljust(64, b"\0")
        expect_err(ERR.PIN_POLICY_VIOLATION, lambda: setpin_raw(b, v2, padded), f"setPIN {what}")
    for proto, n in ((v1, 80), (v1, 48), (v2, 32), (v2, 80)):
        expect_err(ERR.INVALID_PARAMETER, lambda: setpin_raw(b, proto, b"1234".ljust(n, b"\0")),
                   f"setPIN v{proto.VERSION} paddedNewPin {n} bytes")
    expect_err(ERR.PIN_NOT_SET, lambda: pin_token(b), "getPinToken without a PIN")
    cpin(b, v2).set_pin("éééé")   # 4 code points: allowed
    b.connect()
    if b.ctap.get_info().options.get("clientPin") is not True or retries(b) != (8, False):
        raise AssertionError("clientPin not true / retries not 8 after setPIN")
    expect_err(ERR.PIN_AUTH_INVALID, lambda: cpin(b, v1).set_pin(PIN), "setPIN while a PIN is set")
    expect_err(ERR.PIN_INVALID, lambda: cpin(b, v2).change_pin("wrong", PIN), "changePIN, wrong current PIN")
    if retries(b)[0] != 7:
        raise AssertionError(f"retries after a wrong PIN: {retries(b)}")
    cpin(b, v1).change_pin("éééé", "y" * 63)   # 63 bytes: the longest allowed
    cpin(b, v2).change_pin("y" * 63, PIN)
    if retries(b)[0] != 8:
        raise AssertionError("retries not back to 8 after the right PIN")
    # A pinHashEnc of the wrong length (v1: 48 bytes into a 16-byte slot) is a wrong PIN, nothing more.
    expect_err(ERR.PIN_INVALID, lambda: token_raw(b, v1, sha(PIN)[:16] + b"\0" * 32), "v1 pinHashEnc 48 bytes")
    expect_err(ERR.PIN_INVALID, lambda: token_raw(b, v2, sha(PIN)[:16] + b"\0" * 16), "v2 pinHashEnc 48 bytes")
    if retries(b)[0] != 6:
        raise AssertionError(f"retries after two bad-length hashes: {retries(b)}")
    pin_token(b, PIN, proto=v1)
    if retries(b)[0] != 8 or status()["uptime_s"] < up0:
        raise AssertionError("retries not reset, or the board restarted")
    print("   setPIN/changePIN policy, lengths and retries ok, both protocols")


def check_token_permissions(b: Board):
    expect_err(ERR.INVALID_PARAMETER, lambda: b.ctap.client_pin(2, 5, key_agreement={1: 2}, pin_hash_enc=b"\0" * 32,
                                                                permissions=3),
               "getPinToken with permissions")
    for perms, rpid, code, what in ((0, "a.test", ERR.INVALID_PARAMETER, "permissions 0"),
                                    (PERM.BIO_ENROLL, None, ERR.UNAUTHORIZED_PERMISSION, "be"),
                                    (PERM.AUTHENTICATOR_CFG, None, ERR.UNAUTHORIZED_PERMISSION, "acfg"),
                                    (PERM.MAKE_CREDENTIAL, None, ERR.MISSING_PARAMETER, "mc without rpId")):
        expect_err(code, lambda: pin_token(b, PIN, perms, rpid), f"0x09 {what}")
    rp = rand_rp("tok")
    rid = rp["id"]
    for proto in (PinProtocolV1(), PinProtocolV2()):
        v = proto.VERSION
        p, t = pin_token(b, PIN, PERM.MAKE_CREDENTIAL, rid, proto)
        reg = mc_uv(b, rp, p, t)
        if not reg.auth_data.flags & FLAG_UV:
            raise AssertionError(f"v{v}: UV flag not set with a pinUvAuthParam")
        expect_err(ERR.PIN_AUTH_INVALID, lambda: mc_uv(b, rp, p, t), f"v{v}: token reused after UP")
        p, t = pin_token(b, PIN, PERM.MAKE_CREDENTIAL, rid, proto)
        expect_err(ERR.PIN_AUTH_INVALID, lambda: mc_uv(b, rand_rp("other"), p, t), f"v{v}: token for another rpId")
        expect_err(ERR.PIN_AUTH_INVALID, lambda: ga_uv(b, rid, p, t), f"v{v}: mc token used for getAssertion")
        bad = bytes(x ^ 1 for x in t)
        expect_err(ERR.PIN_AUTH_INVALID, lambda: mc_uv(b, rp, p, bad), f"v{v}: wrong token")
        # Legacy getPinToken (mc|ga, no rpId): bound to the first rpId it is used with.
        p, t = pin_token(b, PIN, None, None, proto)
        cid = reg.auth_data.credential_data.credential_id
        a = ga_uv(b, rid, p, t, allow=[{"type": "public-key", "id": cid}])
        if not a.auth_data.flags & FLAG_UV:
            raise AssertionError(f"v{v}: getAssertion UV flag")
    # uv:true is ignored next to a pinUvAuthParam; rejected without one (no built-in UV).
    p, t = pin_token(b, PIN, PERM.MAKE_CREDENTIAL, rid)
    mc_uv(b, rp, p, t, options={"uv": True})
    expect_err(ERR.INVALID_OPTION, lambda: b.ctap.make_credential(cdh(), rp, {"id": b"u"}, ES256_PARAMS,
                                                                  options={"uv": True}), "uv:true alone")


def check_pin_rules(b: Board):
    rp = rand_rp("rules")
    expect_err(ERR.PUAT_REQUIRED, lambda: make_cred(b, rp, rk=True), "rk without pinUvAuthParam, PIN set")
    reg = make_cred(b, rp)   # makeCredUvNotRqd: non-discoverable needs no PIN
    if reg.auth_data.flags & FLAG_UV:
        raise AssertionError("UV flag set without pinUvAuthParam")
    for cmd, payload in ((1, mc_bytes({8: b"", 9: 1})), (2, ga_bytes({6: b"", 7: 1}))):
        st = b.raw_cbor(cmd, payload)[0]
        if st != ERR.PIN_INVALID:
            raise AssertionError(f"cmd {cmd} zero-length pinUvAuthParam with a PIN: {st:#x}")
    for what, cmd, payload, want in (
            ("MC pinUvAuthParam without protocol", 1, mc_bytes({8: b"\0" * 32}), ERR.MISSING_PARAMETER),
            ("GA pinUvAuthProtocol 3", 2, ga_bytes({6: b"\0" * 32, 7: 3}), ERR.INVALID_PARAMETER),
            ("GA wrong pinUvAuthParam", 2, ga_bytes({6: b"\0" * 32, 7: 2}), ERR.PIN_AUTH_INVALID)):
        st = b.raw_cbor(cmd, payload)[0]
        if st != want:
            raise AssertionError(f"{what}: {st:#x}, expected {int(want):#x}")
    if b.raw_cbor(0x0B)[0] != 0:
        raise AssertionError("authenticatorSelection failed")


def check_token_expiry(b: Board):
    rp = rand_rp("exp")
    p, t = pin_token(b, PIN, PERM.MAKE_CREDENTIAL | PERM.GET_ASSERTION, rp["id"])
    time.sleep(31)
    expect_err(ERR.PIN_AUTH_INVALID, lambda: mc_uv(b, rp, p, t), "token after 31 s idle")
    print("   token unusable after 31 s idle")


def check_cred_protect(b: Board):
    rp = rand_rp("cp")
    rid = rp["id"]
    ids, users = {}, {}
    for level in (1, 2, 3):
        p, t = pin_token(b, PIN, PERM.MAKE_CREDENTIAL, rid)
        users[level] = {"id": bytes([level]) * 8, "name": f"name{level}", "displayName": f"disp{level}"}
        reg = mc_uv(b, rp, p, t, rk=True, ext={"credProtect": level, "hmac-secret": True}, user=users[level])
        ad = reg.auth_data
        if ad.extensions != {"credProtect": level, "hmac-secret": True}:
            raise AssertionError(f"credProtect {level}: extensions {ad.extensions}")
        ids[level] = ad.credential_data.credential_id
    if make_cred(b, rand_rp("cp0")).auth_data.extensions:
        raise AssertionError("unsolicited extension output")
    allow = lambda lv: [{"type": "public-key", "id": ids[lv]}]
    # No UV, no allowList: only level 1 is discoverable, and the user entity is id only.
    a = b.ctap.get_assertion(rid, cdh())
    if a.credential["id"] != ids[1] or a.number_of_credentials not in (None, 1) or set(a.user) != {"id"}:
        raise AssertionError(f"no-UV discovery: {a.credential['id'] == ids[1]} n={a.number_of_credentials} {a.user}")
    # No UV, allowList: level 2 usable, level 3 not.
    b.ctap.get_assertion(rid, cdh(), allow(2))
    expect_err(ERR.NO_CREDENTIALS, lambda: b.ctap.get_assertion(rid, cdh(), allow(3)), "level 3 without UV")
    # UV: all three, newest first, with name/displayName.
    p, t = pin_token(b, PIN, PERM.GET_ASSERTION, rid)
    a = ga_uv(b, rid, p, t)
    rest = [b.ctap.get_next_assertion() for _ in range(1, a.number_of_credentials or 1)]
    got = [x.credential["id"] for x in [a] + rest]
    if got != [ids[3], ids[2], ids[1]] or a.user != users[3] or not all(x.auth_data.flags & FLAG_UV for x in rest):
        raise AssertionError(f"UV discovery: order {[list(ids.values()).index(g) + 1 for g in got]} user {a.user}")
    # excludeList: a level 3 credential is invisible without UV, so creation goes ahead; level 2 excludes.
    b.ctap.make_credential(cdh(), rp, {"id": b"x"}, ES256_PARAMS, exclude_list=allow(3))
    expect_err(ERR.CREDENTIAL_EXCLUDED, lambda: b.ctap.make_credential(cdh(), rp, {"id": b"x"}, ES256_PARAMS,
                                                                       exclude_list=allow(2)), "exclude level 2")
    p, t = pin_token(b, PIN, PERM.MAKE_CREDENTIAL, rid)
    expect_err(ERR.CREDENTIAL_EXCLUDED, lambda: mc_uv(b, rp, p, t, exclude=allow(3)), "exclude level 3 with UV")
    # hmac-secret: CredRandomWithUV and CredRandomWithoutUV differ, each is stable.
    s1 = os.urandom(32)
    outs = []
    for uv in (False, True, False, True):
        proto = PinProtocolV2()
        ext, shared = hs_input(b.ctap, proto, [s1])
        if uv:
            p, t = pin_token(b, PIN, PERM.GET_ASSERTION, rid)
            r = ga_uv(b, rid, p, t, allow=allow(2), ext=ext)
        else:
            r = b.ctap.get_assertion(rid, cdh(), allow(2), ext)
        outs.append(hs_outputs(proto, shared, r, 1)[0])
    if outs[0] != outs[2] or outs[1] != outs[3] or outs[0] == outs[1]:
        raise AssertionError("hmac-secret with/without UV: outputs not split or not stable")
    print("   credProtect 1/2/3 discovery, allowList, excludeList and hmac-secret UV split ok")


def check_cred_mgmt(b: Board):
    from fido2.ctap2.credman import CredentialManagement as CM
    p, t = pin_token(b, PIN, PERM.CREDENTIAL_MGMT)
    cm = CM(b.ctap, p, t)
    meta = cm.get_metadata()
    n = meta[CM.RESULT.EXISTING_CRED_COUNT]
    if n + meta[CM.RESULT.MAX_REMAINING_COUNT] != 16 or n < 3:
        raise AssertionError(f"metadata {meta}")
    rps = cm.enumerate_rps()
    if sum(1 for _ in rps) < 1 or any(r[CM.RESULT.RP_ID_HASH] != sha(r[CM.RESULT.RP]["id"]) for r in rps):
        raise AssertionError(f"RPs {rps}")
    cp_rp = [r for r in rps if r[CM.RESULT.RP]["id"].startswith("cp-")][0]
    creds = cm.enumerate_creds(cp_rp[CM.RESULT.RP_ID_HASH])
    levels = sorted(c[CM.RESULT.CRED_PROTECT] for c in creds)
    if levels != [1, 2, 3] or any(c[CM.RESULT.PUBLIC_KEY][3] != -7 for c in creds):
        raise AssertionError(f"credentials {creds}")
    tgt = [c for c in creds if c[CM.RESULT.CRED_PROTECT] == 1][0]
    desc = tgt[CM.RESULT.CREDENTIAL_ID]
    uid = tgt[CM.RESULT.USER]["id"]
    cm.update_user_info(desc, {"id": uid, "name": "renamed"})
    upd = [c for c in cm.enumerate_creds(cp_rp[CM.RESULT.RP_ID_HASH]) if c[CM.RESULT.CREDENTIAL_ID] == desc][0]
    if upd[CM.RESULT.USER] != {"id": uid, "name": "renamed"}:
        raise AssertionError(f"updateUserInformation: {upd[CM.RESULT.USER]}")
    expect_err(ERR.INVALID_PARAMETER, lambda: cm.update_user_info(desc, {"id": b"other", "name": "x"}),
               "update with another user id")
    cm.delete_cred(desc)
    expect_err(ERR.NO_CREDENTIALS, lambda: cm.delete_cred(desc), "delete twice")
    if cm.get_metadata()[CM.RESULT.EXISTING_CRED_COUNT] != n - 1:
        raise AssertionError("count did not drop after delete")
    # A token restricted to an rpId cannot enumerate everything; a token without cm cannot manage.
    p2, t2 = pin_token(b, PIN, PERM.CREDENTIAL_MGMT, cp_rp[CM.RESULT.RP]["id"])
    expect_err(ERR.PIN_AUTH_INVALID, lambda: CM(b.ctap, p2, t2).get_metadata(), "metadata with an rpId token")
    CM(b.ctap, p2, t2).enumerate_creds(cp_rp[CM.RESULT.RP_ID_HASH])
    p3, t3 = pin_token(b, PIN, PERM.GET_ASSERTION, "x.test")
    expect_err(ERR.PIN_AUTH_INVALID, lambda: CM(b.ctap, p3, t3).get_metadata(), "metadata with a ga token")
    print(f"   {n} credentials, {len(rps)} RPs; update, delete and token scoping ok")


def check_fido2_client(b: Board):
    from fido2.client import DefaultClientDataCollector, Fido2Client, UserInteraction

    class UI(UserInteraction):
        asked = 0

        def request_pin(self, permissions, rp_id):
            UI.asked += 1
            return PIN

        def request_uv(self, permissions, rp_id):
            return True

    rid = f"client-{os.urandom(3).hex()}.test"
    client = Fido2Client(b.dev, DefaultClientDataCollector(f"https://{rid}"), UI())
    reg = client.make_credential({
        "rp": {"id": rid, "name": "client"},
        "user": {"id": os.urandom(8), "name": "alice", "displayName": "Alice"},
        "challenge": os.urandom(32),
        "pubKeyCredParams": ES256_PARAMS,
        "authenticatorSelection": {"residentKey": "required", "userVerification": "required"},
        "extensions": {"credentialProtectionPolicy": "userVerificationRequired", "credProps": True},
    })
    ad = reg.response.attestation_object.auth_data
    if not ad.flags & FLAG_UV or ad.extensions.get("credProtect") != 3:
        raise AssertionError(f"Fido2Client register: flags {ad.flags:#x} ext {ad.extensions}")
    sel = client.get_assertion({"challenge": os.urandom(32), "rpId": rid, "userVerification": "required"})
    resp = sel.get_response(0)
    if not resp.response.authenticator_data.flags & FLAG_UV:
        raise AssertionError("Fido2Client assertion without UV flag")
    resp.response.authenticator_data  # parsed
    if UI.asked < 2:
        raise AssertionError(f"PIN requested {UI.asked} times")
    print(f"   register + discoverable sign-in with PIN ({UI.asked} PIN prompts)")


def check_retry_ordering(b: Board):
    """Wrong PINs: retries go down before the compare and survive a reboot; 3 in a row need a power
    cycle (PIN_AUTH_BLOCKED); 8 block the PIN for good (until reset)."""
    def wrong():
        try:
            pin_token(b, "wrong-pin")
        except CtapError as e:
            return e.code
        raise AssertionError("wrong PIN accepted")

    log = []
    left = 8
    while left > 0:
        for i in range(3):
            code = wrong()
            left -= 1
            log.append(f"{code.name}/{retries(b)[0]}")
            want = ERR.PIN_BLOCKED if left == 0 else ERR.PIN_AUTH_BLOCKED if i == 2 else ERR.PIN_INVALID
            if code != want or retries(b)[0] != left:
                raise AssertionError(f"attempt {8 - left}: {code!r} retries {retries(b)}, expected {want!r}/{left}")
            if left == 0:
                break
        if left == 0:
            break
        if retries(b) != (left, True):
            raise AssertionError(f"powerCycleState after 3 failures: {retries(b)}")
        expect_err(ERR.PIN_AUTH_BLOCKED, lambda: pin_token(b, PIN), "right PIN while auth-blocked")
        if retries(b)[0] != left:
            raise AssertionError("an attempt while auth-blocked cost a retry")
        reboot_board()
        b.connect()
        if retries(b) != (left, False):
            raise AssertionError(f"after reboot: {retries(b)}, expected ({left}, False)")
        log.append("reboot")
    expect_err(ERR.PIN_BLOCKED, lambda: pin_token(b, PIN), "right PIN after 8 failures")
    reboot_board()
    b.connect()
    expect_err(ERR.PIN_BLOCKED, lambda: pin_token(b, PIN), "blocked PIN after a reboot")
    print("   " + " ".join(log))


def check_reset_clears_pin(b: Board):
    wipe(b)
    b.connect()
    info = b.ctap.get_info()
    if info.options.get("clientPin") is not False or retries(b) != (8, False) or info.min_pin_length != 4:
        raise AssertionError(f"after reset: clientPin {info.options.get('clientPin')} retries {retries(b)}")
    print(f"   clientPin false, retries 8, /api/fido: {http('/api/fido')}")


# ---- touchless checks (any build) ----

def mc_wait_start(h: RawHid, cid):
    h.send(cid, CBOR_CMD, b"\x01" + mc_bytes())
    kas = []
    r = h.recv(cid, 0.6, kas)
    if r is not None:
        raise AssertionError(f"makeCredential answered without a press: {r}")
    if not kas or set(kas) != {2}:
        raise AssertionError(f"no KEEPALIVE UPNEEDED while waiting: {kas}")
    return kas


def check_wait_cancel_retry(b: Board, h: RawHid):
    cid = h.alloc()
    for attempt in (1, 2):
        mc_wait_start(h, cid)
        h.send(cid, CANCEL_CMD)
        r = h.recv(cid, 2)
        if r != (CBOR_CMD, b"\x2d"):
            raise AssertionError(f"attempt {attempt}: CANCEL gave {r}, expected KEEPALIVE_CANCEL")
    # A CANCEL while idle is ignored and does not poison the next request.
    h.send(cid, CANCEL_CMD)
    mc_wait_start(h, cid)
    h.send(cid, CANCEL_CMD)
    h.recv(cid, 2)


def check_wait_busy_and_init_abort(b: Board, h: RawHid):
    cid, other = h.alloc(), h.alloc()
    mc_wait_start(h, cid)
    h.send(other, PING_CMD, b"x")
    r = h.recv(other)
    if r != (ERROR_CMD, b"\x06"):
        raise AssertionError(f"PING on another CID during the wait: {r}, expected CHANNEL_BUSY")
    nonce = os.urandom(8)
    h.send(cid, INIT_CMD, nonce)
    r = h.recv(cid)
    if not r or r[0] != INIT_CMD or r[1][:8] != nonce:
        raise AssertionError(f"INIT on the waiting CID: {r}")
    kas = []
    r = h.recv(cid, 1.0, kas)
    if r is not None or kas:
        raise AssertionError(f"transaction not abandoned after INIT: reply {r}, keepalives {len(kas)}")
    h.send(cid, PING_CMD, b"y")
    if h.recv(cid) != (PING_CMD, b"y"):
        raise AssertionError("PING after INIT abort failed")


def check_u2f_needs_press(b: Board):
    try:
        b.u2f.register(cdh(), sha("press.test"))
        raise AssertionError("U2F REGISTER succeeded without a press")
    except ApduError as e:
        if e.code != 0x6985:
            raise AssertionError(f"U2F REGISTER without a press: {e.code:#x}, expected 6985")


def check_touch_timeout(b: Board, h: RawHid):
    cid = h.alloc()
    t0 = time.time()
    h.send(cid, CBOR_CMD, b"\x01" + mc_bytes())
    kas = []
    r = h.recv(cid, 35, kas)
    dt = time.time() - t0
    if r != (CBOR_CMD, b"\x2f"):
        raise AssertionError(f"no press: {r} after {dt:.1f} s, expected USER_ACTION_TIMEOUT")
    print(f"   USER_ACTION_TIMEOUT after {dt:.1f} s, {len(kas)} keepalives")


# ---- runner ----

def wipe(b: Board) -> Board:
    """Reboot, then CTAP reset inside the 10 s window (auto-granted on a test build)."""
    up_at = reboot_board()
    b.connect()
    if time.time() - up_at > 9:
        raise AssertionError("reconnect took too long for the reset window")
    print("   reset (press BOOT now unless this is a test build)")
    b.ctap.reset()
    return b


def run(checks, b: Board):
    failed = []
    for name, fn in checks:
        print(f"-- {name}")
        try:
            b.connect()
            fn()
            print("   ok")
        except Exception as e:   # report and carry on with the remaining checks
            print(f"   FAIL: {type(e).__name__}: {e}")
            failed.append(name)
    return failed


def main() -> int:
    st = status()
    test_build = bool(st.get("test_build"))
    print(f"firmware {st.get('fw')} test_build={test_build} efuse_virtual={st.get('efuse_virtual')}")
    b = Board()
    if sys.argv[1:] == ["--wipe"]:
        wipe(b)
        print("wiped")
        return 0
    if test_build:
        print("-- wipe: reboot and reset in the window")
        wipe(b)
    h = RawHid(b.dev.descriptor)
    h.drain(0.2)

    if not test_build:
        checks = [
            ("getInfo", lambda: check_get_info(b)),
            ("HID channels, CID 0 and unallocated CIDs rejected", lambda: check_hid_channels(b, h)),
            ("INIT resync mid-assembly", lambda: check_init_resync(b, h)),
            ("wait: CANCEL then retry (no poisoning)", lambda: check_wait_cancel_retry(b, h)),
            ("wait: other CID busy, INIT aborts the transaction", lambda: check_wait_busy_and_init_abort(b, h)),
            ("U2F REGISTER needs a press", lambda: check_u2f_needs_press(b)),
            ("CBOR depth and item limits", lambda: check_cbor_limits(b)),
            ("touch required: USER_ACTION_TIMEOUT", lambda: check_touch_timeout(b, h)),
        ]
        failed = run(checks, b)
        print("touchless checks:", "all passed" if not failed else f"FAILED {failed}")
        return 1 if failed else 0

    state = {}

    def counter_before_reboot():
        rp = rand_rp("ctr")
        cid = make_cred(b, rp).auth_data.credential_data.credential_id
        state["ctr"] = (rp["id"], cid, ga_counter(b, rp["id"], cid)[0])

    def counter_after_reboot():
        rp_id, cid, before = state["ctr"]
        reboot_board()
        b.connect()
        after = ga_counter(b, rp_id, cid)[0]
        if after <= before:
            raise AssertionError(f"counter went from {before} to {after} across a reboot")
        print(f"   counter {before} -> {after} across reboot")

    def hmac_before():
        state["hmac"] = check_hmac_secret(b)

    def hmac_after():
        rid, c1, s1, out, pub = state["hmac"]
        for proto in (PinProtocolV1(), PinProtocolV2()):
            (o,) = hs_assert(b.ctap, proto, rid, c1, [s1], pub)
            if o != out:
                raise AssertionError("hmac-secret output changed across the reboot")

    checks = [
        ("getInfo", lambda: check_get_info(b)),
        ("error-code table", lambda: check_error_table(b)),
        ("zero-length pinUvAuthParam", lambda: check_zero_len_pin_auth(b)),
        ("CBOR depth and item limits", lambda: check_cbor_limits(b)),
        ("HID channels, CID 0 and unallocated CIDs rejected", lambda: check_hid_channels(b, h)),
        ("INIT resync mid-assembly", lambda: check_init_resync(b, h)),
        ("CANCEL then retry (no poisoning)", lambda: check_cancel_then_retry_auto(b, h)),
        ("packed self attestation", lambda: check_packed_self_attestation(b)),
        ("U2F batch attestation, REGISTER P1=0 and P1=3", lambda: check_u2f_attestation(b)),
        ("U2F <-> CTAP2 cross assertions", lambda: check_cross_protocol(b)),
        ("U2F check-only / enforce / dont-enforce", lambda: check_u2f_modes(b)),
        ("up:false probe", lambda: check_up_false(b)),
        ("allowList mismatch: no resident fallback", lambda: check_allowlist_no_fallback(b)),
        ("rk overwrite, user entity id only", lambda: check_rk_overwrite_and_user(b)),
        ("getNextAssertion", lambda: check_next_assertion(b)),
        ("hmac-secret", hmac_before),
        ("resident store full (KEY_STORE_FULL), overwrite still allowed", lambda: check_key_store_full(b)),
        ("counter before reboot", counter_before_reboot),
        ("counter monotonic across reboot", counter_after_reboot),
        ("hmac-secret output stable across reboot", hmac_after),
        ("reset outside the 10 s window", lambda: (time.sleep(max(0, 11 - status()["uptime_s"])),
                                                    check_reset_outside_window(b))),
        ("wipe before the PIN checks", lambda: wipe(b)),
        ("setPIN / changePIN: policy, lengths, retries", lambda: check_set_pin(b)),
        ("pinUvAuthToken: permissions, rpId binding, single use, UV flag", lambda: check_token_permissions(b)),
        ("PIN set: rk needs pinUvAuthParam, zero-length probe, selection", lambda: check_pin_rules(b)),
        ("credProtect levels and hmac-secret UV split", lambda: check_cred_protect(b)),
        ("credentialManagement", lambda: check_cred_mgmt(b)),
        ("Fido2Client with PIN", lambda: check_fido2_client(b)),
        ("pinUvAuthToken expiry", lambda: check_token_expiry(b)),
        ("PIN retries: ordering, power cycle, block", lambda: check_retry_ordering(b)),
        ("reset clears the PIN", lambda: check_reset_clears_pin(b)),
    ]
    failed = run(checks, b)
    print("all checks passed" if not failed else f"FAILED: {failed}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
