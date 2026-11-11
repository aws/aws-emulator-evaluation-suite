"""mfa-device-full-lifecycle."""
from __future__ import annotations

import base64
import email.utils
import hashlib
import hmac
import struct
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "mfa-device-full-lifecycle"
GROUP = "state-machine"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateVirtualMFADevice -> EnableMFADevice -> GetMFADevice -> ResyncMFADevice ->
    DeactivateMFADevice -> DeleteVirtualMFADevice transitions correctly; device disappears
    from ListMFADevices/ListVirtualMFADevices at each terminal step."""
    iam = ctx.client("iam")

    resource_tags = [{"Key": "sim2real-check", "Value": CHECK}]

    user_name = ctx.unique_name("sim2real-mfauser-")
    iam.create_user(UserName=user_name, Tags=resource_tags)
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    device_name = ctx.unique_name("sim2real-mfadev-")
    device = iam.create_virtual_mfa_device(
        VirtualMFADeviceName=device_name, Tags=resource_tags
    )["VirtualMFADevice"]
    serial = device["SerialNumber"]
    seed = device["Base32StringSeed"]
    if isinstance(seed, bytes):
        seed = seed.decode()
    ctx.on_cleanup(lambda: _best_effort_delete_virtual_mfa(iam, serial))

    # Device is unassigned right after creation.
    virtual_before = iam.list_virtual_mfa_devices(AssignmentStatus="Unassigned")["VirtualMFADevices"]
    assert any(d["SerialNumber"] == serial for d in virtual_before), "new device missing from Unassigned list"

    # The TOTP codes must be computed against AWS's clock, not the local
    # test-runner clock: if the runner's wall clock is skewed from AWS's by
    # more than the ~30s validity window, every locally-computed code is
    # wrong no matter how many times it is regenerated/retried. Estimate the
    # skew from a real response's Date header and apply it consistently.
    clock_offset = _clock_offset(iam)

    enabled_counter = _enable_mfa_device_with_retry(ctx, iam, user_name, serial, seed, clock_offset)
    ctx.on_cleanup(lambda: _best_effort_deactivate(iam, user_name, serial))

    devices = iam.list_mfa_devices(UserName=user_name)["MFADevices"]
    assert len(devices) == 1 and devices[0]["SerialNumber"] == serial, (
        f"expected exactly one MFA device ({serial}) on user after enable, got {devices}"
    )
    assert "EnableDate" in devices[0], f"enabled device missing EnableDate: {devices[0]}"

    # GetMFADevice only supports FIDO security-key ARNs, not TOTP virtual-MFA serial
    # numbers -- calling it against our (now-enabled) virtual device is rejected, but as
    # a request-shape/validation error (the serial doesn't match the expected FIDO ARN
    # format) rather than as an unknown-entity error.
    code, message = _error(lambda: iam.get_mfa_device(SerialNumber=serial, UserName=user_name))
    assert code == "ValidationError", f"expected ValidationError from GetMFADevice on virtual MFA, got {code}"
    expected = (
        "The MFA device serial number sent in the request is invalid or not supported by this API. "
        "Currently, only hardware FIDO security keys are supported. "
        "Please use the compatible device or API."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # IAM treats each TOTP code as single-use: codes from a window EnableMFADevice consumed are
    # rejected InvalidAuthenticationCode. Resync sends only the two windows after the consumed
    # ones, retrying until IAM's clock accepts them.
    _resync_mfa_device_with_retry(ctx, iam, user_name, serial, seed, clock_offset, enabled_counter)

    iam.deactivate_mfa_device(UserName=user_name, SerialNumber=serial)
    devices_after_deactivate = iam.list_mfa_devices(UserName=user_name)["MFADevices"]
    assert devices_after_deactivate == [], "device still listed for user after DeactivateMFADevice"

    iam.delete_virtual_mfa_device(SerialNumber=serial)
    remaining = iam.list_virtual_mfa_devices(AssignmentStatus="Any")["VirtualMFADevices"]
    assert not any(d["SerialNumber"] == serial for d in remaining), "device still present after delete"

    # The deleted device is not just absent from the list -- it is gone: a second delete on the
    # same (now nonexistent) serial fails NoSuchEntity rather than succeeding as a no-op.
    code_double_delete, double_delete_message = _error(
        lambda: iam.delete_virtual_mfa_device(SerialNumber=serial)
    )
    assert code_double_delete == "NoSuchEntity", (
        f"expected NoSuchEntity deleting an already-deleted virtual MFA device, got {code_double_delete}"
    )
    expected = f"MFA Device with serial number {serial} does not exist."
    assert double_delete_message == expected, f"expected message {expected!r}, got {double_delete_message!r}"


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _totp_code(base32_seed: str, counter: int) -> str:
    key = base64.b32decode(base32_seed, casefold=True)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code_int = (struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF) % 1_000_000
    return f"{code_int:06d}"


def _clock_offset(iam) -> float:
    """Best-effort estimate of (AWS server time - local time), in seconds.

    TOTP codes are only valid within a narrow (~30s) window of the true
    time. If the local test-runner clock is skewed from AWS's clock, every
    locally-computed authentication code will be wrong regardless of how
    many times it is regenerated/retried, so we must anchor our counter to
    AWS's clock rather than assuming the local clock is accurate.
    """
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


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _enable_mfa_device_with_retry(ctx, iam, user_name, serial, seed, clock_offset, timeout=60, interval=1) -> int:
    """EnableMFADevice with codes for the previous or current window, retrying
    InvalidAuthenticationCode at a window boundary; returns the last counter consumed."""
    from botocore.exceptions import ClientError

    deadline = time.time() + _budget_s(ctx, timeout)
    while True:
        cur = int(time.time() + clock_offset) // 30
        err = None
        for base in (cur - 1, cur):
            try:
                iam.enable_mfa_device(
                    UserName=user_name,
                    SerialNumber=serial,
                    AuthenticationCode1=_totp_code(seed, base),
                    AuthenticationCode2=_totp_code(seed, base + 1),
                )
                return base + 1
            except ClientError as e:
                if e.response["Error"]["Code"] != "InvalidAuthenticationCode":
                    raise
                err = e
        if time.time() + interval >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"EnableMFADevice {serial} accepting a current TOTP pair: the run budget ended first; not graded") from err
            raise err
        time.sleep(interval)


def _resync_mfa_device_with_retry(
    ctx, iam, user_name, serial, seed, clock_offset, enabled_counter, timeout=75, interval=1
) -> None:
    """ResyncMFADevice with codes from the first windows after enabled_counter, retrying
    InvalidAuthenticationCode until IAM's clock reaches them."""
    from botocore.exceptions import ClientError

    deadline = time.time() + _budget_s(ctx, timeout)
    while True:
        cur = int(time.time() + clock_offset) // 30
        base = max(cur, enabled_counter + 1)
        try:
            iam.resync_mfa_device(
                UserName=user_name,
                SerialNumber=serial,
                AuthenticationCode1=_totp_code(seed, base),
                AuthenticationCode2=_totp_code(seed, base + 1),
            )
            return
        except ClientError as err:
            if err.response["Error"]["Code"] != "InvalidAuthenticationCode":
                raise
            if time.time() + interval >= deadline:
                if _budget_spent(ctx):
                    raise TimeoutError(f"ResyncMFADevice {serial} accepting a current TOTP pair: the run budget ended first; not graded") from err
                raise
        time.sleep(interval)


def _best_effort_deactivate(iam, user_name, serial) -> None:
    from botocore.exceptions import ClientError

    try:
        iam.deactivate_mfa_device(UserName=user_name, SerialNumber=serial)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _best_effort_delete_virtual_mfa(iam, serial) -> None:
    from botocore.exceptions import ClientError

    try:
        iam.delete_virtual_mfa_device(SerialNumber=serial)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
