"""deactivate-mfa-device-not-enrolled-rejected."""
from __future__ import annotations

import base64
import hashlib
import hmac
import struct
import time
from typing import Any

from behavioral_harness import tags

CHECK = "deactivate-mfa-device-not-enrolled-rejected"
GROUP = "overly-permissive"
SERVICES = ["iam"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeactivateMFADevice rejects a serial number that is not currently enrolled for the given
    user with NoSuchEntity; the identical call succeeds once the device is actually enrolled."""
    iam = ctx.client("iam")
    user_name = ctx.unique_name("sim2real-mfa-deact-")
    iam.create_user(UserName=user_name)
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    device_name = ctx.unique_name("sim2real-mfa-deact-dev-")
    device = iam.create_virtual_mfa_device(VirtualMFADeviceName=device_name)["VirtualMFADevice"]
    serial = device["SerialNumber"]
    secret_b32 = device["Base32StringSeed"].decode("ascii")
    ctx.on_cleanup(lambda: iam.delete_virtual_mfa_device(SerialNumber=serial))

    # Break the precondition: the device was created but never enabled for this user.
    code, message = _error(lambda: iam.deactivate_mfa_device(UserName=user_name, SerialNumber=serial))
    assert code == "NoSuchEntity", f"expected NoSuchEntity for an unenrolled device, got {code}"
    expected = "MFA Device invalid for user."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Positive control: once enrolled, the identical call succeeds.
    _enable_with_retry(ctx, iam, user_name, serial, secret_b32)
    iam.deactivate_mfa_device(UserName=user_name, SerialNumber=serial)
    remaining = iam.list_mfa_devices(UserName=user_name)["MFADevices"]
    assert remaining == [], f"expected no MFA devices listed for the user after deactivation, got {remaining}"


def _totp_code(secret_b32: str, counter: int, digits: int = 6) -> str:
    padding = "=" * ((8 - len(secret_b32) % 8) % 8)
    key = base64.b32decode(secret_b32.upper() + padding)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code_int = (struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF) % (10**digits)
    return str(code_int).zfill(digits)


def _enable_with_retry(ctx, iam, user_name: str, serial: str, secret_b32: str, step: int = 30) -> None:
    """EnableMFADevice with a fresh consecutive TOTP pair, retrying InvalidAuthenticationCode
    across a 30-second window boundary until IAM's clock accepts one."""
    from botocore.exceptions import ClientError

    deadline = time.time() + 60
    while True:
        counter = int(time.time() // step)
        try:
            iam.enable_mfa_device(
                UserName=user_name,
                SerialNumber=serial,
                AuthenticationCode1=_totp_code(secret_b32, counter),
                AuthenticationCode2=_totp_code(secret_b32, counter + 1),
            )
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidAuthenticationCode" or time.time() > deadline:
                raise
            time.sleep(2)


def _error(fn: Any) -> tuple[str, str]:
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises, because an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"real AWS rejects deactivating a device never enrolled for the user, but it SUCCEEDED "
        f"and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
