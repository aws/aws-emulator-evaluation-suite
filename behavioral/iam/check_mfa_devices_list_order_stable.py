"""mfa-devices-list-order-stable."""
from __future__ import annotations

import base64
import hashlib
import hmac
import struct
import time

from behavioral_harness import tags

CHECK = "mfa-devices-list-order-stable"
GROUP = "ordering"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListMFADevices returns a user's devices in a stable order across repeated calls with no
    intervening mutation, and returns exactly the enabled devices; AWS documents no particular
    order, so the enabled set is compared order-insensitively."""
    iam = ctx.client("iam")
    user_name = ctx.unique_name("sim2real-mfa-user-")
    iam.create_user(UserName=user_name, Tags=[{"Key": "sim2real-check", "Value": CHECK}])
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    enabled_in_order = []
    for i in range(3):
        device_name = ctx.unique_name(f"sim2real-mfa-dev{i}-")
        device = iam.create_virtual_mfa_device(
            VirtualMFADeviceName=device_name,
            Tags=[{"Key": "sim2real-check", "Value": CHECK}],
        )["VirtualMFADevice"]
        serial = device["SerialNumber"]
        seed = device["Base32StringSeed"]
        ctx.on_cleanup(lambda s=serial: iam.delete_virtual_mfa_device(SerialNumber=s))

        counter = int(time.time() // 30)
        code1 = _totp_code(seed, counter)
        code2 = _totp_code(seed, counter + 1)
        iam.enable_mfa_device(
            UserName=user_name,
            SerialNumber=serial,
            AuthenticationCode1=code1,
            AuthenticationCode2=code2,
        )
        ctx.on_cleanup(lambda s=serial: iam.deactivate_mfa_device(UserName=user_name, SerialNumber=s))
        enabled_in_order.append(serial)
        time.sleep(1.5)  # keep enable timestamps distinguishable between devices

    first_call_devices = iam.list_mfa_devices(UserName=user_name)["MFADevices"]
    first_call = [d["SerialNumber"] for d in first_call_devices]
    second_call = [d["SerialNumber"] for d in iam.list_mfa_devices(UserName=user_name)["MFADevices"]]

    assert first_call == second_call, (
        f"ListMFADevices order changed across repeated calls: {first_call!r} vs {second_call!r}"
    )
    assert first_call == enabled_in_order or sorted(first_call) == sorted(enabled_in_order), (
        f"ListMFADevices returned {first_call!r}, not the enabled devices {enabled_in_order!r}"
    )


def _totp_code(secret_b32, counter: int) -> str:
    if isinstance(secret_b32, bytes):
        secret_b32 = secret_b32.decode("ascii")
    padding = "=" * ((8 - len(secret_b32) % 8) % 8)
    key = base64.b32decode(secret_b32 + padding, casefold=True)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 1_000_000
    return f"{code:06d}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
