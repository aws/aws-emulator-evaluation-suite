"""op-contract-resync-mfa-device."""
from __future__ import annotations

import base64
import hashlib
import hmac
import struct
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-resync-mfa-device"
GROUP = "error-semantics"
SERVICES = ["iam"]

_BAD_CODE_MESSAGE = "Authentication code for device is not valid."


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ResyncMFADevice accepts two fresh consecutive TOTP codes and rejects codes that don't match the device secret."""
    iam = ctx.client("iam")
    user_name = ctx.unique_name("sim2real-mfa-user-")
    device_name = ctx.unique_name("sim2real-mfa-device-")

    iam.create_user(UserName=user_name)
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    device = iam.create_virtual_mfa_device(VirtualMFADeviceName=device_name)["VirtualMFADevice"]
    serial = device["SerialNumber"]
    seed_bytes = device["Base32StringSeed"]
    secret = seed_bytes.decode("ascii") if isinstance(seed_bytes, bytes) else seed_bytes
    ctx.on_cleanup(lambda: iam.delete_virtual_mfa_device(SerialNumber=serial))

    used_counter = _enable_with_retry(iam, user_name, serial, secret)
    ctx.on_cleanup(lambda: iam.deactivate_mfa_device(UserName=user_name, SerialNumber=serial))

    devices = iam.list_mfa_devices(UserName=user_name)["MFADevices"]
    assert any(d["SerialNumber"] == serial for d in devices), "device not associated with the user after enable"

    # Real IAM treats each TOTP code as single-use (replay protection): generating the
    # resync codes from "now" immediately after enable_mfa_device succeeded can land in
    # the same 30s window (or the very next one) as the codes already consumed by
    # enable, causing a spurious InvalidAuthenticationCode. Advance past those consumed
    # windows before deriving the resync codes.
    _wait_past_totp_window(used_counter)

    # Success path: resync with two fresh consecutive codes succeeds (device is/remains in sync).
    _resync_with_retry(iam, user_name, serial, secret)

    # Rejection boundary: codes that don't match the device secret are refused.
    code, message = _error(
        lambda: iam.resync_mfa_device(
            UserName=user_name, SerialNumber=serial, AuthenticationCode1="000000", AuthenticationCode2="111111"
        )
    )
    # Real IAM's wire error code for this shape has no "Exception" suffix.
    assert code == "InvalidAuthenticationCode", f"expected InvalidAuthenticationCode, got {code}"
    assert message == _BAD_CODE_MESSAGE, (
        f"InvalidAuthenticationCode message: expected {_BAD_CODE_MESSAGE!r}, got {message!r}"
    )

    # Effect absent: the rejected resync left the device's enrollment untouched --
    # an independent read at the destination, not the failed call's own response.
    devices_after = iam.list_mfa_devices(UserName=user_name)["MFADevices"]
    assert any(d["SerialNumber"] == serial for d in devices_after), (
        f"device {serial} lost its association with {user_name} after a rejected resync"
    )


def _error(fn):
    """The ClientError's (code, message); a successful call fails the refusal claim."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"the call succeeded where AWS refuses it and returned {result!r}")


def _totp_code(secret_b32: str, for_time: float) -> str:
    padded = secret_b32.upper()
    padded += "=" * ((8 - len(padded) % 8) % 8)
    key = base64.b32decode(padded)
    counter = int(for_time // 30)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code_int = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 1_000_000
    return f"{code_int:06d}"


def _enable_with_retry(iam, user_name, serial, secret, attempts=4):
    last_exc = None
    for _ in range(attempts):
        now = time.time()
        code1 = _totp_code(secret, now)
        code2 = _totp_code(secret, now + 30)
        try:
            iam.enable_mfa_device(
                UserName=user_name,
                SerialNumber=serial,
                AuthenticationCode1=code1,
                AuthenticationCode2=code2,
            )
            # Return the TOTP counter (30s window index) of the second, later code
            # that was just consumed, so callers can avoid reusing/overlapping it.
            return int((now + 30) // 30)
        except ClientError as exc:
            last_exc = exc
            if exc.response["Error"]["Code"] != "InvalidAuthenticationCode":
                raise
            time.sleep(2)
    raise AssertionError(f"could not enable MFA device after {attempts} attempts: {last_exc}")


def _wait_past_totp_window(consumed_counter, windows_ahead=2, cap_seconds=180):
    """Bounded poll: block until the current 30s TOTP window is safely past the one
    already consumed by a prior enable/resync call, so freshly generated codes are
    guaranteed not to collide with already-used ones."""
    deadline = time.time() + cap_seconds
    target_counter = consumed_counter + windows_ahead
    while int(time.time() // 30) < target_counter:
        if time.time() > deadline:
            raise AssertionError("timed out waiting for a fresh TOTP window")
        time.sleep(1)


def _resync_with_retry(iam, user_name, serial, secret, attempts=4):
    last_exc = None
    for _ in range(attempts):
        now = time.time()
        code1 = _totp_code(secret, now)
        code2 = _totp_code(secret, now + 30)
        try:
            iam.resync_mfa_device(
                UserName=user_name,
                SerialNumber=serial,
                AuthenticationCode1=code1,
                AuthenticationCode2=code2,
            )
            return
        except ClientError as exc:
            last_exc = exc
            if exc.response["Error"]["Code"] != "InvalidAuthenticationCode":
                raise
            time.sleep(2)
    raise AssertionError(f"could not resync MFA device after {attempts} attempts: {last_exc}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
