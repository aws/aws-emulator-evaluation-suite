"""invalid-mfa-authentication-code-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "invalid-mfa-authentication-code-rejected"
GROUP = 'errors'
SERVICES = ['iam']


def _error(fn):
    """``(code, message)`` of a call real AWS refuses; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"real AWS refuses this call, but it succeeded and returned {result!r}")


def _totp_code(secret_b32, offset_steps=0, step=30, digits=6):
    import base64
    import hashlib
    import hmac
    import struct

    # Base32StringSeed is a blob member, so botocore hands it back as bytes; normalize to str.
    if isinstance(secret_b32, (bytes, bytearray)):
        secret_b32 = secret_b32.decode("ascii")
    padding = "=" * ((8 - len(secret_b32) % 8) % 8)
    key = base64.b32decode(secret_b32.upper() + padding)
    counter = int(time.time() // step) + offset_steps
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code_int = (struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF) % (10**digits)
    return str(code_int).zfill(digits)


def _resync_with_valid_codes(iam, user_name, serial, seed, attempts=6, wait_s=31):
    # ResyncMFADevice enforces a short anti-replay window: a code pair drawn from (or
    # overlapping) the window already consumed by the immediately preceding
    # EnableMFADevice call can be bounced with InvalidAuthenticationCode even though it
    # is otherwise correct. Retry with a freshly computed pair a full TOTP step apart
    # until a never-submitted window is used.
    last_err = None
    for _ in range(attempts):
        code1 = _totp_code(seed, offset_steps=0)
        code2 = _totp_code(seed, offset_steps=1)
        try:
            iam.resync_mfa_device(
                UserName=user_name,
                SerialNumber=serial,
                AuthenticationCode1=code1,
                AuthenticationCode2=code2,
            )
            return
        except ClientError as exc:
            last_err = exc
            time.sleep(wait_s)
    raise AssertionError(f"resync with genuinely valid codes never succeeded: {last_err}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ResyncMFADevice with two codes that do not match the device's TOTP secret fails with
    InvalidAuthenticationCode and its exact message, the device stays listed for the user, and the
    same call with valid codes succeeds."""
    iam = ctx.client("iam")
    device_name = ctx.unique_name("sim2real-behav-mfa-")
    created = iam.create_virtual_mfa_device(VirtualMFADeviceName=device_name)
    serial = created["VirtualMFADevice"]["SerialNumber"]
    seed = created["VirtualMFADevice"]["Base32StringSeed"]
    ctx.on_cleanup(lambda: iam.delete_virtual_mfa_device(SerialNumber=serial))

    user_name = ctx.unique_name("sim2real-behav-user-")
    iam.create_user(UserName=user_name)
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    code1 = _totp_code(seed, offset_steps=0)
    code2 = _totp_code(seed, offset_steps=1)
    iam.enable_mfa_device(
        UserName=user_name, SerialNumber=serial, AuthenticationCode1=code1, AuthenticationCode2=code2
    )
    ctx.on_cleanup(lambda: iam.deactivate_mfa_device(UserName=user_name, SerialNumber=serial))

    # Two authentication codes that are syntactically valid (6 digits) but deliberately wrong.
    bad_code1 = "000000" if code1 != "000000" else "111111"
    bad_code2 = "999999" if code2 != "999999" else "888888"
    code_bad, message_bad = _error(
        lambda: iam.resync_mfa_device(
            UserName=user_name,
            SerialNumber=serial,
            AuthenticationCode1=bad_code1,
            AuthenticationCode2=bad_code2,
        )
    )
    assert code_bad == "InvalidAuthenticationCode", (
        f"expected InvalidAuthenticationCode for a wrong resync code, got {code_bad}"
    )
    expected_message = "Authentication code for device is not valid."
    assert message_bad == expected_message, (
        f"the wrong resync codes must be refused with AWS's exact message {expected_message!r}; "
        f"got {message_bad!r}"
    )

    # Positive control: the identical ResyncMFADevice call succeeds against genuinely
    # valid codes for this device, proving the rejection above was about the code
    # values and not a target that refuses every resync outright.
    _resync_with_valid_codes(iam, user_name, serial, seed)

    devices = iam.list_mfa_devices(UserName=user_name)["MFADevices"]
    assert serial in [d["SerialNumber"] for d in devices], (
        "MFA device must remain associated with the user after the rejected resync and the "
        "subsequent successful one"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
