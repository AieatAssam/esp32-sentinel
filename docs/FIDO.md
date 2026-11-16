# FIDO2 and U2F

The device is a FIDO authenticator over USB HID, using CTAPHID. It implements CTAP 2.1
(`main/fido/ctap2.c`) and U2F (`main/fido/u2f.c`). The CTAPHID framing is in
`main/fido/ctaphid.c`. Credentials and PIN state are stored in `main/fido/store.c`.

This is an experimental implementation. It has not been checked against a conformance
suite, and it is not certified.

## Advertised capabilities (authenticatorGetInfo)

- Versions: `U2F_V2`, `FIDO_2_0`, `FIDO_2_1`.
- Extensions: `credProtect`, `hmac-secret`.
- Options: `rk` true, `up` true, `plat` false, `credMgmt` true, `pinUvAuthToken` true,
  `makeCredUvNotRqd` true. `clientPin` is true only when a PIN is set.
- `pinUvAuthProtocols`: 2 and 1.
- `maxCredentialCountInList`: 8. Transports: `usb`. Algorithm: ES256 (-7).
- AAGUID: `a3ed f539 29e0 5abf 6459 9462 327a 45e8`.
- Minimum PIN length: the larger of 4 and the stored minimum. Maximum PIN length: 63 bytes.

## Commands

| CTAP2 command | Code | Notes |
|---|---|---|
| makeCredential | 0x01 | ES256 required in `pubKeyCredParams` |
| getAssertion | 0x02 | |
| getInfo | 0x04 | |
| clientPIN | 0x06 | Subcommands below |
| reset | 0x07 | Only within 10 s of power-up, presence required |
| getNextAssertion | 0x08 | Pending assertion cleared unless this command follows |
| credentialManagement | 0x0A | Subcommands below |
| authenticatorSelection | 0x0B | Returns the presence result |

clientPIN subcommands: 0x01 getRetries, 0x02 getKeyAgreement, 0x03 setPIN,
0x04 changePIN, 0x05 getPINToken (protocol 1), 0x09 getPinUvAuthTokenUsingPinWithPermissions
(protocol 2). Built-in user verification (0x06, 0x07) is rejected with `ST_INVALID_SUBCMD`.

credentialManagement subcommands: 0x01 getCredsMetadata (existing and remaining counts),
0x02 enumerateRPsBegin, 0x03 enumerateRPsGetNextRP, 0x04 enumerateCredentialsBegin
(takes an rpIdHash), 0x05 enumerateCredentialsGetNextCredential, 0x06 deleteCredential,
0x07 updateUserInformation. All except 0x03 and 0x05 need a PIN auth. Enumeration with a
token bound to one RP ID is refused.

A canonical-CBOR check runs before the CBOR parser sees a request. It rejects
non-canonical encoding and enforces a nesting depth and size limit (`main/fido/cbor_check.h`).

## PIN

- The PIN is stored as the first 16 bytes of its SHA-256 digest, encrypted and
  authenticated under keys derived from the master secret.
- Retries: 8 (`STORE_PIN_RETRIES`). The retry count is saved before the PIN is
  compared, so a power cut does not reset it.
- After 3 wrong PINs in a row (`PIN_MAX_CONSEC`), PIN auth is blocked until the next
  power cycle (`ST_PIN_AUTH_BLOCKED`). At 0 retries the PIN is blocked (`ST_PIN_BLOCKED`).
- PIN protocols 1 and 2 are both accepted.

The dashboard shows whether a PIN is set and the retries left, under "Security key" in
"Advanced". It reads `pin_set` and `pin_retries` from `GET /api/fido`.

PIN limit, stated plainly: without flash encryption, a flash dump allows offline PIN
guessing with no retry limit. The 8-try counter protects only against online guessing
over USB. Hardening moves the master key out of flash, which removes the offline
exposure (see below).

## Tokens and user verification

- PIN tokens (`pinUvAuthToken`) carry permissions: makeCredential `0x01`, getAssertion
  `0x02`, credentialManagement `0x04`.
- A token expires after 30 s without use (rolling), and in any case after 600 s.
- A token's permissions are cleared after a request that collected user presence.
- The only user verification is the PIN. There is no built-in UV. A request with `uv`
  set and no `pinUvAuthParam` is refused (`ST_INVALID_OPTION`).
- With a PIN set, makeCredential with `rk` true and no `pinUvAuthParam` returns
  `ST_PUAT_REQUIRED`.

## makeCredential and getAssertion

- makeCredential with `up` set to false is refused (`ST_INVALID_OPTION`).
- getAssertion with `up` set to false does not wait for a press. This is the silent
  probe path.
- Attestation is packed self attestation, with algorithm -7 and no `x5c`. The signature
  covers `authData || clientDataHash`.
- credProtect: level 3 requires user verification (the PIN). Level 2 requires user
  verification, or the credential to be on the allow list.
- hmac-secret works over ECDH with protocols 1 and 2, using `saltEnc` and `saltAuth`. Two
  secrets are derived: one for requests with UV, one for requests without UV.
- Resident credentials: at most 16 (`FIDO_MAX_RESIDENT`). Credential IDs are 48 bytes.
  User IDs are at most 64 bytes, RP IDs at most 128.
- Signature counter: it is batched. Flash is written once per 16 signatures
  (`STORE_CTR_BATCH`). After a power loss the counter can jump ahead, but never backwards.

## U2F

- The U2F batch key and certificate are in `main/fido/attest_batch.h`. The key is public.
  The certificate is self-signed. Its subject is "S3 Sentinel U2F batch attestation
  (public key, untrusted)", so it identifies no device.
- A U2F request is answered with `0x6985` at once, unless user presence was latched. A
  press seen in the last 2 s (`U2F_WINDOW_US`) is latched for 3 s (`U2F_LATCH_US`) and
  used by the next request (`main/fido/fido.c`).
- Authentication requests that do not require presence are signed without a press. The
  counter is reported but not advanced, so no flash write happens without a press.

## User presence

- Presence is a press of the BOOT button, waited for in `main/fido/fido.c`. Each touch
  check waits for a tap.
- A press cannot confirm two actions. `fido_button_claim` and `fido_button_release`
  guard this.
- Admin operations (reset, harden) wait up to 30 s for a press (`ADMIN_TOUCH_MS`).
- In a release build, a FIDO touch is a tap. A hold of 3 s on BOOT is needed for the
  CTAPHID download command (see [SECURITY.md](../SECURITY.md)).

## Master secret, reset and hardening

- Until hardening, the master secret is stored as plaintext in NVS (namespace `fido`,
  key `msec`).
- `POST /api/fido/reset` (BOOT press): removes resident credentials and the PIN. It
  replaces the master secret and keeps the signature counter.
- `POST /api/fido/harden` with the body `{"confirm":"BURN"}` (BOOT press):
  - picks a free eFuse key block from `EFUSE_BLK_KEY0` to `EFUSE_BLK_KEY5` and writes a
    random key to it, with purpose `HMAC_UP`. The master key is then derived by the HMAC
    peripheral and not stored in flash;
  - erases resident credentials (`store_harden()`);
  - re-saves the PIN after `store_harden()` runs (`ctap2_harden()`), also when erasing
    resident credentials failed.

The eFuse burn is irreversible. No command in this repository reverses it. Back up what
you need first. Once hardening is done, treat the credentials on the device as lost if
you reset the key.

## Test support

`tools/fido_test.py` runs against a board built with `sdkconfig.test`. That config sets
`CONFIG_FIDO_TEST_AUTO_UP=y`, which grants user presence without a press, and
`CONFIG_EFUSE_VIRTUAL=y`, which keeps eFuses in RAM. It needs `fido2` 2.x and
`cryptography`. It has a `--wipe` option.

Never flash a test build onto a board that holds credentials you care about.
