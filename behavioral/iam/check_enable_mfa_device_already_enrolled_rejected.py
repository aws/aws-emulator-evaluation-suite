"""enable-mfa-device-already-enrolled-rejected."""
from __future__ import annotations

import base64
import email.utils
import hashlib
import hmac
import struct
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "enable-mfa-device-already-enrolled-rejected"
GROUP = "overly-permissive"
SERVICES = ["iam"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Re-enabling a user's already-active MFA device is rejected EntityAlreadyExists with exactly
    one device still enrolled; after deactivation the identical call succeeds again."""
    iam = ctx.client("iam")
    username = ctx.unique_name("sim2real-mfa-reenable-")
    device_name = ctx.unique_name("sim2real-mfa-reenable-dev-")

    iam.create_user(UserName=username)
    ctx.on_cleanup(lambda: iam.delete_user(UserName=username))

    device = iam.create_virtual_mfa_device(VirtualMFADeviceName=device_name)["VirtualMFADevice"]
    serial = device["SerialNumber"]
    seed = device["Base32StringSeed"]
    ctx.on_cleanup(lambda: iam.delete_virtual_mfa_device(SerialNumber=serial))

    # TOTP codes are valid only within ~30s of AWS's clock, so compute them against AWS's clock,
    # and retry InvalidAuthenticationCode: a correct code can be rejected right after device
    # creation, before the device is visible to the replica that validates it.
    clock_offset = _clock_offset(iam)
    # Highest TOTP counter a successful enable consumed; later enables send only newer codes.
    used = {"counter": None}

    _enable_retrying_skew(ctx, iam, username, serial, seed, clock_offset, used)
    ctx.on_cleanup(lambda: _safe_deactivate(iam, username, serial))

    # Positive control: the device is now genuinely enrolled for the user.
    devices = iam.list_mfa_devices(UserName=username)["MFADevices"]
    assert len(devices) == 1 and devices[0]["SerialNumber"] == serial

    # Negative: re-enabling the same, already-assigned device with fresh valid codes.
    code, message = _error(lambda: _enable_retrying_skew(ctx, iam, username, serial, seed, clock_offset, used))
    assert code == "EntityAlreadyExists", f"expected EntityAlreadyExists, got {code}"
    expected_message = f"MFA Device for user {username} already exists."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: still exactly one MFA device enrolled for the user -- no duplicate.
    devices_after = iam.list_mfa_devices(UserName=username)["MFADevices"]
    assert len(devices_after) == 1 and devices_after[0]["SerialNumber"] == serial

    # Restore: deactivating clears the already-enrolled state that caused the rejection.
    iam.deactivate_mfa_device(UserName=username, SerialNumber=serial)
    devices_deactivated = iam.list_mfa_devices(UserName=username)["MFADevices"]
    assert devices_deactivated == [], f"expected no MFA devices after deactivate, got {devices_deactivated}"

    # The identical call now succeeds: the earlier rejection tracked the
    # already-enrolled state, not the device or user themselves.
    _enable_retrying_skew(ctx, iam, username, serial, seed, clock_offset, used)
    devices_restored = iam.list_mfa_devices(UserName=username)["MFADevices"]
    assert len(devices_restored) == 1 and devices_restored[0]["SerialNumber"] == serial, (
        f"expected device re-enrolled after restore, got {devices_restored}"
    )


def _totp(secret_b32, for_time: float, step: int = 30, digits: int = 6) -> str:
    seed_bytes = secret_b32.encode() if isinstance(secret_b32, str) else secret_b32
    padding = (-len(seed_bytes)) % 8
    seed_bytes += b"=" * padding
    key = base64.b32decode(seed_bytes, casefold=True)
    counter = int(for_time // step)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code_int = (struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF) % (10**digits)
    return str(code_int).zfill(digits)


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _enable_retrying_skew(ctx, iam, username, serial, seed, clock_offset, used, timeout=60, interval=1) -> None:
    """EnableMFADevice with codes from windows no earlier enable consumed, retrying while AWS
    says the code itself is invalid (clock drift, a not-yet-current window, or the device not
    yet visible to the replica that validates it). Any other outcome is terminal."""
    from botocore.exceptions import ClientError

    deadline = time.time() + _budget_s(ctx, timeout)
    while True:
        cur = int((time.time() + clock_offset) // 30)
        floor = cur - 1 if used["counter"] is None else used["counter"] + 1
        bases = sorted({max(cur - 1, floor), max(cur, floor)})
        err = None
        for base in bases:
            try:
                iam.enable_mfa_device(
                    UserName=username,
                    SerialNumber=serial,
                    AuthenticationCode1=_totp(seed, base * 30),
                    AuthenticationCode2=_totp(seed, (base + 1) * 30),
                )
                used["counter"] = base + 1
                return
            except ClientError as e:
                if e.response["Error"]["Code"] != "InvalidAuthenticationCode":
                    raise
                err = e
        if time.time() + interval >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"EnableMFADevice {serial} accepting a current TOTP pair: the run budget ended first; not graded") from err
            raise err
        time.sleep(interval)


def _safe_deactivate(iam, username, serial) -> None:
    from botocore.exceptions import ClientError

    try:
        iam.deactivate_mfa_device(UserName=username, SerialNumber=serial)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _clock_offset(iam) -> float:
    """Best-effort estimate of (AWS server time - local time), in seconds."""
    local_before = time.time()
    try:
        resp = iam.list_users(MaxItems=1)
    except Exception:
        return 0.0
    local_after = time.time()
    headers = resp.get("ResponseMetadata", {}).get("HTTPHeaders", {})
    date_hdr = headers.get("date")
    if not date_hdr:
        return 0.0
    try:
        server_ts = email.utils.parsedate_to_datetime(date_hdr).timestamp()
    except Exception:
        return 0.0
    return server_ts - (local_before + local_after) / 2


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
