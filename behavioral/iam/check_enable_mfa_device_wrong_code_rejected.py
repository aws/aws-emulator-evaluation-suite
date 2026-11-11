"""enable-mfa-device-wrong-code-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "enable-mfa-device-wrong-code-rejected"
GROUP = "state-machine"
SERVICES = ["iam"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """EnableMFADevice with codes that do not match the device's TOTP seed fails with
    InvalidAuthenticationCode and its exact message and leaves the device unassigned;
    the same call with the device's real TOTP codes assigns it."""
    iam = ctx.client("iam")
    user_name = ctx.unique_name("sim2real-behav-mfawrong-")
    device_name = ctx.unique_name("sim2real-behav-mfawrongdev-")

    iam.create_user(UserName=user_name)
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_user(UserName=user_name)))

    device = iam.create_virtual_mfa_device(VirtualMFADeviceName=device_name)["VirtualMFADevice"]
    serial = device["SerialNumber"]
    seed = device["Base32StringSeed"]
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_virtual_mfa_device(SerialNumber=serial)))

    code, message = _error(
        lambda: iam.enable_mfa_device(
            UserName=user_name,
            SerialNumber=serial,
            AuthenticationCode1="000000",
            AuthenticationCode2="111111",
        )
    )
    assert code == "InvalidAuthenticationCode", f"expected InvalidAuthenticationCode, got {code!r}"
    expected_message = "Authentication code for device is not valid."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    unassigned = iam.list_virtual_mfa_devices(AssignmentStatus="Unassigned")["VirtualMFADevices"]
    assert any(d["SerialNumber"] == serial for d in unassigned), (
        f"expected {serial} among Unassigned devices after the rejected wrong-code enable, "
        f"got serials {[d['SerialNumber'] for d in unassigned]!r}"
    )
    assigned = iam.list_virtual_mfa_devices(AssignmentStatus="Assigned")["VirtualMFADevices"]
    assert not any(d["SerialNumber"] == serial for d in assigned), (
        f"expected {serial} absent from Assigned devices after the rejected wrong-code enable, "
        f"got serials {[d['SerialNumber'] for d in assigned]!r}"
    )

    # Positive control (restore leg): the identical call, given the device's real TOTP code,
    # must succeed -- ruling out a target that rejects every EnableMFADevice call regardless
    # of code.
    now = time.time()
    iam.enable_mfa_device(
        UserName=user_name,
        SerialNumber=serial,
        AuthenticationCode1=_totp(seed, now),
        AuthenticationCode2=_totp(seed, now + 30),
    )
    ctx.on_cleanup(
        lambda: _safe(lambda: iam.deactivate_mfa_device(UserName=user_name, SerialNumber=serial))
    )

    assigned_after = iam.list_virtual_mfa_devices(AssignmentStatus="Assigned")["VirtualMFADevices"]
    assert any(d["SerialNumber"] == serial for d in assigned_after), (
        f"expected {serial} among Assigned devices once enabled with the real TOTP code, "
        f"got serials {[d['SerialNumber'] for d in assigned_after]!r}"
    )


def _safe(fn) -> None:
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _error(fn) -> tuple:
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected EnableMFADevice to be rejected, but it succeeded: {result!r}")


def _totp(secret_b32, for_time: float, step: int = 30, digits: int = 6) -> str:
    import base64
    import hashlib
    import hmac
    import struct

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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
