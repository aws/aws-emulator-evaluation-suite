"""virtual-mfa-device-lifecycle."""
from __future__ import annotations

import base64
import hashlib
import hmac
import struct
import time

from behavioral_harness import tags

CHECK = "virtual-mfa-device-lifecycle"
GROUP = "state-machine"
SERVICES = ["iam"]

_MSG_GET_MFA = (
    "The MFA device serial number sent in the request is invalid or not supported by this API. "
    "Currently, only hardware FIDO security keys are supported. Please use the compatible device or API."
)


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An MFA device transitions unassigned->enabled->deactivated->deleted and disappears from both list endpoints."""
    from botocore.exceptions import ClientError

    iam = ctx.client("iam")
    user_name = ctx.unique_name("sim2real-behav-mfauser-")
    device_name = ctx.unique_name("sim2real-behav-mfadevice-")

    iam.create_user(UserName=user_name)
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    device = iam.create_virtual_mfa_device(VirtualMFADeviceName=device_name)["VirtualMFADevice"]
    serial = device["SerialNumber"]
    seed_b32 = device["Base32StringSeed"]
    ctx.on_cleanup(lambda: _ignore_no_such_entity(lambda: iam.delete_virtual_mfa_device(SerialNumber=serial)))

    unassigned = {d["SerialNumber"] for d in iam.list_virtual_mfa_devices(AssignmentStatus="Unassigned")["VirtualMFADevices"]}
    assert serial in unassigned

    code1 = _totp(seed_b32, offset_steps=-1)
    code2 = _totp(seed_b32, offset_steps=0)
    iam.enable_mfa_device(
        UserName=user_name,
        SerialNumber=serial,
        AuthenticationCode1=code1,
        AuthenticationCode2=code2,
    )
    ctx.on_cleanup(
        lambda: _ignore_no_such_entity(lambda: iam.deactivate_mfa_device(UserName=user_name, SerialNumber=serial))
    )

    devices = iam.list_mfa_devices(UserName=user_name)["MFADevices"]
    assert any(d["SerialNumber"] == serial for d in devices)

    assigned = {d["SerialNumber"] for d in iam.list_virtual_mfa_devices(AssignmentStatus="Assigned")["VirtualMFADevices"]}
    assert serial in assigned

    try:
        got = iam.get_mfa_device(SerialNumber=serial)
    except AttributeError:
        pass  # GetMFADevice not present in this botocore version; not fatal to the lifecycle check
    except ClientError as exc:
        # GetMFADevice is scoped to FIDO security-key ARNs, not TOTP virtual-MFA serial
        # numbers -- AWS has withdrawn this operation's applicability to our device type,
        # and that refusal is itself the contract to assert (a target that answers instead
        # of rejecting is diverging from real AWS).
        err = exc.response.get("Error", {})
        assert err.get("Code") == "ValidationError", (
            f"expected ValidationError from GetMFADevice on a virtual MFA serial, got {err!r}"
        )
        assert err.get("Message") == _MSG_GET_MFA, (err.get("Message"), _MSG_GET_MFA)
    else:
        assert False, f"GetMFADevice unexpectedly succeeded for a virtual MFA serial: {got}"

    iam.deactivate_mfa_device(UserName=user_name, SerialNumber=serial)

    devices = iam.list_mfa_devices(UserName=user_name)["MFADevices"]
    assert not any(d["SerialNumber"] == serial for d in devices)

    unassigned_after = {d["SerialNumber"] for d in iam.list_virtual_mfa_devices(AssignmentStatus="Unassigned")["VirtualMFADevices"]}
    assert serial in unassigned_after

    iam.delete_virtual_mfa_device(SerialNumber=serial)

    all_after = {d["SerialNumber"] for d in iam.list_virtual_mfa_devices(AssignmentStatus="Any")["VirtualMFADevices"]}
    assert serial not in all_after


def _ignore_no_such_entity(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _totp(secret_b32, offset_steps: int = 0, digits: int = 6, period: int = 30) -> str:
    if isinstance(secret_b32, bytes):
        secret_b32 = secret_b32.decode("ascii")
    padded = secret_b32.upper() + "=" * ((8 - len(secret_b32) % 8) % 8)
    key = base64.b32decode(padded)
    counter = int(time.time() // period) + offset_steps
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF) % (10**digits)
    return f"{code:0{digits}d}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
