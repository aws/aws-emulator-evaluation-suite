"""resync-mfa-device-invalid-code-rejected."""
from __future__ import annotations

import base64
import hashlib
import hmac
import struct
import time

from behavioral_harness import tags

CHECK = "resync-mfa-device-invalid-code-rejected"
GROUP = "error-semantics"
SERVICES = ["iam"]

_BAD_CODE_MESSAGE = "Authentication code for device is not valid."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ResyncMFADevice with two codes that do not match the device's TOTP seed
    fails with InvalidAuthenticationCode and its exact message, the device stays
    associated with the user, and a resync with consecutive valid codes succeeds."""
    iam = ctx.client("iam")
    tag_value = ctx.unique_name("sim2real-resync-mfa-device-invalid-code-rejected-")
    user_name = ctx.unique_name("sim2real-mfa-user-")
    iam.create_user(UserName=user_name, Tags=[{"Key": "sim2real", "Value": tag_value}])
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    device_name = ctx.unique_name("sim2real-mfa-device-")
    device = iam.create_virtual_mfa_device(
        VirtualMFADeviceName=device_name,
        Tags=[{"Key": "sim2real", "Value": tag_value}],
    )["VirtualMFADevice"]
    serial = device["SerialNumber"]
    ctx.on_cleanup(lambda: iam.delete_virtual_mfa_device(SerialNumber=serial))

    seed_raw = device["Base32StringSeed"]
    seed_str = seed_raw.decode("ascii") if isinstance(seed_raw, bytes) else seed_raw
    seed_str += "=" * ((8 - len(seed_str) % 8) % 8)
    secret = base64.b32decode(seed_str, casefold=True)

    _enable_device_with_retry(iam, user_name, serial, secret)
    ctx.on_cleanup(lambda: iam.deactivate_mfa_device(UserName=user_name, SerialNumber=serial))

    # Positive control: freshly computed, genuinely consecutive codes for the
    # same device succeed (no exception). This must hold *before* the negative
    # below can mean anything -- otherwise "rejects these codes" is indistinguishable
    # from "rejects every resync for this device".
    _resync_with_retry(iam, user_name, serial, secret)

    # Negative: two codes that cannot possibly validate against this seed.
    code, message = _error(
        lambda: iam.resync_mfa_device(
            UserName=user_name,
            SerialNumber=serial,
            AuthenticationCode1="000000",
            AuthenticationCode2="000001",
        )
    )
    assert code == "InvalidAuthenticationCode", f"expected InvalidAuthenticationCode, got {code!r}"
    assert message == _BAD_CODE_MESSAGE, (
        f"InvalidAuthenticationCode message: expected {_BAD_CODE_MESSAGE!r}, got {message!r}"
    )

    # Effect absent, via an independent read (ListMFADevices, not ResyncMFADevice):
    # the rejected resync must not have knocked the device loose from the user.
    devices_after = iam.list_mfa_devices(UserName=user_name)["MFADevices"]
    serials_after = [d["SerialNumber"] for d in devices_after]
    assert serial in serials_after, (
        f"device {serial!r} must remain associated with {user_name!r} after a rejected "
        f"resync; ListMFADevices returned {serials_after!r}"
    )


def _error(fn):
    """The ClientError's (code, message); a successful call fails the refusal claim."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"the call succeeded where AWS refuses it and returned {result!r}")


def _totp(secret: bytes, for_time: float, digits: int = 6, step: int = 30) -> str:
    counter = int(for_time // step)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(secret, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code_int = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code_int).zfill(digits)


def _enable_device_with_retry(iam, user_name, serial, secret, attempts=3):
    from botocore.exceptions import ClientError
    last_err = None
    for _ in range(attempts):
        now = time.time()
        code1, code2 = _totp(secret, now), _totp(secret, now + 30)
        try:
            iam.enable_mfa_device(
                UserName=user_name,
                SerialNumber=serial,
                AuthenticationCode1=code1,
                AuthenticationCode2=code2,
            )
            return
        except ClientError as e:
            last_err = e
            time.sleep(1)
    raise AssertionError(f"could not enable MFA device: {last_err}")


def _resync_with_retry(iam, user_name, serial, secret, attempts=6, wait=31):
    # ResyncMFADevice enforces a short anti-replay window on the AWS side: codes
    # drawn from (or overlapping) the same TOTP window already consumed by the
    # immediately preceding EnableMFADevice/ResyncMFADevice call can be bounced
    # with InvalidAuthenticationCodeException even though they are otherwise
    # correct. Each retry waits a full TOTP step (30s) plus margin so a fresh,
    # never-submitted code pair is used, and enough attempts are made to clear
    # any transient backend propagation delay.
    from botocore.exceptions import ClientError
    last_err = None
    for _ in range(attempts):
        now = time.time()
        code1, code2 = _totp(secret, now), _totp(secret, now + 30)
        try:
            iam.resync_mfa_device(
                UserName=user_name,
                SerialNumber=serial,
                AuthenticationCode1=code1,
                AuthenticationCode2=code2,
            )
            return
        except ClientError as e:
            last_err = e
            time.sleep(wait)
    raise AssertionError(f"could not resync MFA device with valid codes: {last_err}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
