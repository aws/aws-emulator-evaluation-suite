"""mfa-devices-per-user-quota-exceeded-rejected."""
from __future__ import annotations

import base64
import hashlib
import hmac
import struct
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "mfa-devices-per-user-quota-exceeded-rejected"
GROUP = "state-machine"
SERVICES = ["iam"]

_QUOTA_MESSAGE = "Cannot exceed quota limit for MFADevicesPerUser"


def _totp_code(seed_b32: str, step_offset: int = 0, digits: int = 6, period_s: int = 30) -> str:
    """RFC 6238 TOTP for a base32 seed, at ``step_offset`` steps from the current one."""
    if isinstance(seed_b32, bytes):
        seed_b32 = seed_b32.decode("ascii")
    seed_b32 = seed_b32.upper()
    seed_b32 += "=" * (-len(seed_b32) % 8)
    key = base64.b32decode(seed_b32)
    counter = int(time.time() // period_s) + step_offset
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    truncated = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return f"{truncated % (10 ** digits):0{digits}d}"


def _teardown_device(iam, user_name: str, serial: str):
    """Deactivate (if associated) then delete a virtual MFA device; tolerate it already being gone."""

    def run_undo() -> None:
        try:
            iam.deactivate_mfa_device(UserName=user_name, SerialNumber=serial)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_virtual_mfa_device(SerialNumber=serial)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    return run_undo


def _enable(iam, user_name: str, serial: str, seed_b32: str, timeout_s: float = 95.0) -> None:
    """EnableMFADevice with the current TOTP pair; InvalidAuthenticationCode means the pair crossed
    a 30-second step, so it waits for the next step and tries again. Other errors raise."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            iam.enable_mfa_device(
                UserName=user_name,
                SerialNumber=serial,
                AuthenticationCode1=_totp_code(seed_b32, -1),
                AuthenticationCode2=_totp_code(seed_b32, 0),
            )
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidAuthenticationCode" or time.monotonic() >= deadline:
                raise
        time.sleep(30 - time.time() % 30 + 1)


def _error(fn):
    """``(code, message)`` of the ClientError ``fn`` raises; an unexpected success raises instead."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected this call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A user may have at most 8 MFA devices enabled; a 9th EnableMFADevice is refused
    LimitExceeded and freeing one of the 8 lets a 9th device be enabled."""
    iam = ctx.client("iam")
    user_name = ctx.unique_name("sim2real-behav-mfaq-")
    iam.create_user(UserName=user_name, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    serials = []
    for i in range(8):
        device_name = ctx.unique_name(f"sim2real-behav-mfaq-dev{i}-")
        device = iam.create_virtual_mfa_device(
            VirtualMFADeviceName=device_name, Tags=[{"Key": "sim2real", "Value": CHECK}]
        )["VirtualMFADevice"]
        serial = device["SerialNumber"]
        ctx.on_cleanup(_teardown_device(iam, user_name, serial))
        _enable(iam, user_name, serial, device["Base32StringSeed"])
        serials.append(serial)

    enabled = {d["SerialNumber"] for d in iam.list_mfa_devices(UserName=user_name)["MFADevices"]}
    assert enabled == set(serials), f"expected exactly the 8 enabled devices {serials!r}, got {sorted(enabled)!r}"

    overflow_name = ctx.unique_name("sim2real-behav-mfaq-overflow-")
    overflow_device = iam.create_virtual_mfa_device(
        VirtualMFADeviceName=overflow_name, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )["VirtualMFADevice"]
    overflow_serial = overflow_device["SerialNumber"]
    ctx.on_cleanup(_teardown_device(iam, user_name, overflow_serial))

    code, message = _error(
        lambda: _enable(iam, user_name, overflow_serial, overflow_device["Base32StringSeed"])
    )
    assert code == "LimitExceeded", f"expected LimitExceeded enabling a 9th MFA device, got {code!r}"
    assert message == _QUOTA_MESSAGE, f"expected the exact quota message {_QUOTA_MESSAGE!r}, got {message!r}"

    enabled_after_refusal = {d["SerialNumber"] for d in iam.list_mfa_devices(UserName=user_name)["MFADevices"]}
    assert enabled_after_refusal == set(serials), (
        f"the rejected 9th EnableMFADevice must not have changed the enabled set, got {sorted(enabled_after_refusal)!r}"
    )

    freed = serials[0]
    iam.deactivate_mfa_device(UserName=user_name, SerialNumber=freed)
    _enable(iam, user_name, overflow_serial, overflow_device["Base32StringSeed"])

    enabled_final = {d["SerialNumber"] for d in iam.list_mfa_devices(UserName=user_name)["MFADevices"]}
    want_final = set(serials[1:]) | {overflow_serial}
    assert enabled_final == want_final, (
        f"freeing one of the 8 slots must let the 9th device be enabled; expected {sorted(want_final)!r}, "
        f"got {sorted(enabled_final)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
