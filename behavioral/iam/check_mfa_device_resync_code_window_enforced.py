"""mfa-device-resync-code-window-enforced."""
from __future__ import annotations

import base64
import hashlib
import hmac
import struct
import time

from behavioral_harness import tags

CHECK = "mfa-device-resync-code-window-enforced"
GROUP = "visibility-timeout-ttl"
SERVICES = ["iam"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ResyncMFADevice rejects wrong codes and non-consecutive codes from the real secret with
    InvalidAuthenticationCode, leaving the device enrolled; fresh consecutive codes then succeed."""
    iam = ctx.client("iam")
    username = ctx.unique_name("sim2real-mfa-resync-")
    device_name = ctx.unique_name("sim2real-mfa-resync-dev-")

    iam.create_user(UserName=username)
    ctx.on_cleanup(lambda: iam.delete_user(UserName=username))

    device = iam.create_virtual_mfa_device(VirtualMFADeviceName=device_name)["VirtualMFADevice"]
    serial = device["SerialNumber"]
    seed = device["Base32StringSeed"]
    ctx.on_cleanup(lambda: iam.delete_virtual_mfa_device(SerialNumber=serial))

    consumed = _enable_with_retry(ctx, iam, username, serial, seed)
    ctx.on_cleanup(lambda: iam.deactivate_mfa_device(UserName=username, SerialNumber=serial))

    code, message = _error(
        lambda: iam.resync_mfa_device(
            UserName=username, SerialNumber=serial, AuthenticationCode1="000000", AuthenticationCode2="111111"
        )
    )
    assert code == "InvalidAuthenticationCode", f"expected InvalidAuthenticationCode, got {code}"
    expected = "Authentication code for device is not valid."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    devices = iam.list_mfa_devices(UserName=username)["MFADevices"]
    assert len(devices) == 1 and devices[0]["SerialNumber"] == serial

    # Advance to a never-submitted window so the rejection is about the skipped step, not IAM's
    # single-use replay protection on the codes enable_mfa_device consumed.
    skip_counter = _wait_for_counter(ctx, consumed + 1)
    skip1 = _totp(seed, skip_counter * 30)
    skip2 = _totp(seed, (skip_counter + 2) * 30)  # one window further than the required +1
    code2_result, code2_result_message = _error(
        lambda: iam.resync_mfa_device(
            UserName=username, SerialNumber=serial, AuthenticationCode1=skip1, AuthenticationCode2=skip2
        )
    )
    assert code2_result == "InvalidAuthenticationCode", f"expected InvalidAuthenticationCode, got {code2_result}"
    expected = "Authentication code for device is not valid."
    assert code2_result_message == expected, f"expected message {expected!r}, got {code2_result_message!r}"

    devices_after = iam.list_mfa_devices(UserName=username)["MFADevices"]
    assert len(devices_after) == 1 and devices_after[0]["SerialNumber"] == serial

    # Positive control: consecutive codes from windows the enable did not consume.
    _resync_with_retry(ctx, iam, username, serial, seed, consumed + 1)

    devices_final = iam.list_mfa_devices(UserName=username)["MFADevices"]
    assert len(devices_final) == 1 and devices_final[0]["SerialNumber"] == serial


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
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _counter(step: int = 30) -> int:
    return int(time.time() // step)


def _enable_with_retry(ctx, iam, username: str, serial: str, seed, timeout: float = 60) -> int:
    """EnableMFADevice with codes for the previous or current window, retrying
    InvalidAuthenticationCode at a window boundary; returns the last counter consumed."""
    from botocore.exceptions import ClientError

    deadline = time.time() + _budget_s(ctx, timeout)
    while True:
        cur = _counter()
        err = None
        for base in (cur - 1, cur):
            try:
                iam.enable_mfa_device(
                    UserName=username,
                    SerialNumber=serial,
                    AuthenticationCode1=_totp(seed, base * 30),
                    AuthenticationCode2=_totp(seed, (base + 1) * 30),
                )
                return base + 1
            except ClientError as e:
                if e.response["Error"]["Code"] != "InvalidAuthenticationCode":
                    raise
                err = e
        if time.time() + 1 >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"EnableMFADevice {serial} accepting a current TOTP pair: the run budget ended first; not graded") from err
            raise err
        time.sleep(1)


def _wait_for_counter(ctx, target: int, timeout: float = 75) -> int:
    """Wait (bounded) until the TOTP window reaches target, a window no call has submitted."""
    deadline = time.time() + _budget_s(ctx, timeout)
    while _counter() < target:
        if time.time() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"TOTP window {target}: the run budget ended first; not graded")
            raise AssertionError(f"timed out waiting for TOTP window {target}")
        time.sleep(1)
    return _counter()


def _resync_with_retry(ctx, iam, username: str, serial: str, seed, first_fresh: int, timeout: float = 75) -> None:
    """Resync with consecutive codes from windows no enable consumed, retrying
    InvalidAuthenticationCode until IAM's clock accepts them."""
    from botocore.exceptions import ClientError

    deadline = time.time() + _budget_s(ctx, timeout)
    last_err = None
    while True:
        cur = _counter()
        for base in sorted({max(cur - 1, first_fresh), max(cur, first_fresh)}):
            try:
                iam.resync_mfa_device(
                    UserName=username,
                    SerialNumber=serial,
                    AuthenticationCode1=_totp(seed, base * 30),
                    AuthenticationCode2=_totp(seed, (base + 1) * 30),
                )
                return
            except ClientError as err:
                if err.response["Error"]["Code"] != "InvalidAuthenticationCode":
                    raise
                last_err = err
        if time.time() + 1 >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"ResyncMFADevice {serial} accepting fresh codes: the run budget ended first; not graded")
            raise AssertionError(f"could not resync MFA device with genuinely valid codes: {last_err}")
        time.sleep(1)

if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
