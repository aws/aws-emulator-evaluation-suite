"""mfa-device-delete-while-enabled-rejected."""
from __future__ import annotations

import base64
import hashlib
import hmac
import struct
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "mfa-device-delete-while-enabled-rejected"
GROUP = "state-machine"
SERVICES = ["iam"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteVirtualMFADevice must be rejected with DeleteConflict while the device is still
    enabled/assigned to a user, and the SAME delete call must succeed once the device is
    deactivated -- proving the rejection is specific to the enabled state, not universal."""
    iam = ctx.client("iam")
    user_name = ctx.unique_name("sim2real-mfadelconflict-")
    device_name = ctx.unique_name("sim2real-mfadelconflictdev-")
    iam.create_user(UserName=user_name)
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    # Positive control: an unassigned virtual MFA device deletes cleanly, so a later rejection
    # cannot be "DeleteVirtualMFADevice always fails" in disguise.
    baseline_name = ctx.unique_name("sim2real-mfadelconflictbase-")
    baseline_serial = iam.create_virtual_mfa_device(VirtualMFADeviceName=baseline_name)[
        "VirtualMFADevice"
    ]["SerialNumber"]
    iam.delete_virtual_mfa_device(SerialNumber=baseline_serial)
    baseline_remaining = {
        d["SerialNumber"] for d in iam.list_virtual_mfa_devices()["VirtualMFADevices"]
    }
    assert baseline_serial not in baseline_remaining, (
        f"positive control: an unassigned virtual MFA device {baseline_serial} must delete "
        f"cleanly, but it is still listed in {baseline_remaining}"
    )

    device = iam.create_virtual_mfa_device(VirtualMFADeviceName=device_name)[
        "VirtualMFADevice"
    ]
    serial = device["SerialNumber"]
    seed = device["Base32StringSeed"]
    ctx.on_cleanup(lambda: _best_effort_delete_device(iam, serial))

    _enable_with_retry(iam, user_name, serial, seed)
    ctx.on_cleanup(lambda: _best_effort_deactivate(iam, user_name, serial))

    code, message = _error(lambda: iam.delete_virtual_mfa_device(SerialNumber=serial))
    assert code == "DeleteConflict", (
        f"expected DeleteConflict while MFA device is enabled, got {code}"
    )
    expected = "MFA VirtualDevice in use. Must deactivate first."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # device must still be assigned since the delete was rejected
    assigned = {
        d["SerialNumber"]
        for d in iam.list_virtual_mfa_devices(AssignmentStatus="Assigned")[
            "VirtualMFADevices"
        ]
    }
    assert serial in assigned, (
        f"expected {serial} to remain assigned since the delete was rejected, got {assigned}"
    )

    # Restore: deactivate the device, then the IDENTICAL delete call must now succeed.
    iam.deactivate_mfa_device(UserName=user_name, SerialNumber=serial)
    iam.delete_virtual_mfa_device(SerialNumber=serial)

    remaining = {d["SerialNumber"] for d in iam.list_virtual_mfa_devices()["VirtualMFADevices"]}
    assert serial not in remaining, (
        f"expected {serial} gone after the restored delete, got {remaining}"
    )

    code2, code2_message = _error(lambda: iam.delete_virtual_mfa_device(SerialNumber=serial))
    assert code2 == "NoSuchEntity", (
        f"deleting the already-deleted device {serial} again must return NoSuchEntity, got {code2}"
    )
    expected = f"MFA Device with serial number {serial} does not exist."
    assert code2_message == expected, f"expected message {expected!r}, got {code2_message!r}"


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _best_effort_delete_device(iam, serial: str) -> None:
    try:
        iam.delete_virtual_mfa_device(SerialNumber=serial)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _best_effort_deactivate(iam, user_name: str, serial: str) -> None:
    try:
        iam.deactivate_mfa_device(UserName=user_name, SerialNumber=serial)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _totp(secret_b32: str, for_time: float, digits: int = 6, interval: int = 30) -> str:
    key = base64.b32decode(secret_b32.upper(), casefold=True)
    counter = int(for_time // interval)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code_int = (struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF) % (
        10**digits
    )
    return str(code_int).zfill(digits)


def _enable_with_retry(iam, user_name: str, serial: str, seed: str, attempts: int = 4) -> None:
    last_exc = None
    for _ in range(attempts):
        now = time.time()
        code1 = _totp(seed, now)
        code2 = _totp(seed, now + 30)
        try:
            iam.enable_mfa_device(
                UserName=user_name,
                SerialNumber=serial,
                AuthenticationCode1=code1,
                AuthenticationCode2=code2,
            )
            return
        except ClientError as exc:
            last_exc = exc
            if exc.response["Error"]["Code"] == "InvalidAuthenticationCode":
                time.sleep(2.0)
                continue
            raise
    raise AssertionError(f"EnableMFADevice never succeeded: {last_exc}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
