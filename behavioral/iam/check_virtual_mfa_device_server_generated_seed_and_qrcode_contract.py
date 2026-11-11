"""virtual-mfa-device-server-generated-seed-and-qrcode-contract."""
from __future__ import annotations

import base64
import email.utils
import hashlib
import hmac
import string
import struct
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "virtual-mfa-device-server-generated-seed-and-qrcode-contract"
GROUP = "server-side"
SERVICES = ["iam"]

_BASE32_CHARSET = set(string.ascii_uppercase + "234567")
_PNG_MAGIC = b"\x89PNG\r\n\x1a\n"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateVirtualMFADevice returns a base32 seed and PNG QR code that differ per device, and
    each seed is a working TOTP secret: EnableMFADevice accepts codes derived from it."""
    iam = ctx.client("iam")

    name_a = ctx.unique_name("sim2real-mfa-seed-a-")
    name_b = ctx.unique_name("sim2real-mfa-seed-b-")
    user_a = ctx.unique_name("sim2real-mfa-seed-user-a-")
    user_b = ctx.unique_name("sim2real-mfa-seed-user-b-")

    device_a = iam.create_virtual_mfa_device(VirtualMFADeviceName=name_a)["VirtualMFADevice"]
    ctx.on_cleanup(lambda: _best_effort_delete_virtual_mfa(iam, device_a["SerialNumber"]))
    device_b = iam.create_virtual_mfa_device(VirtualMFADeviceName=name_b)["VirtualMFADevice"]
    ctx.on_cleanup(lambda: _best_effort_delete_virtual_mfa(iam, device_b["SerialNumber"]))

    for device in (device_a, device_b):
        seed_bytes = device["Base32StringSeed"]
        seed = seed_bytes.decode("ascii") if isinstance(seed_bytes, bytes) else seed_bytes
        assert len(seed) > 0, "Base32StringSeed must not be empty"
        assert set(seed) <= _BASE32_CHARSET, f"seed {seed!r} contains non-base32 characters"

        qr = device["QRCodePNG"]
        qr_bytes = bytes(qr)
        assert len(qr_bytes) > 0, "QRCodePNG must not be empty"
        assert qr_bytes.startswith(_PNG_MAGIC), "QRCodePNG must be a well-formed PNG"

    seed_a = device_a["Base32StringSeed"]
    seed_b = device_b["Base32StringSeed"]
    assert seed_a != seed_b, "two independently created devices must not share a seed"

    qr_a = bytes(device_a["QRCodePNG"])
    qr_b = bytes(device_b["QRCodePNG"])
    assert qr_a != qr_b, "two independently created devices must not share a QR code image"

    # Shape checks pass for any noise; enabling with derived TOTP codes proves the seed works.
    iam.create_user(UserName=user_a)
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_a))
    iam.create_user(UserName=user_b)
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_b))

    clock_offset = _clock_offset(iam)

    for user, device in ((user_a, device_a), (user_b, device_b)):
        serial = device["SerialNumber"]
        seed = device["Base32StringSeed"]
        if isinstance(seed, bytes):
            seed = seed.decode("ascii")

        counter = int(time.time() + clock_offset) // 30
        iam.enable_mfa_device(
            UserName=user,
            SerialNumber=serial,
            AuthenticationCode1=_totp_code(seed, counter),
            AuthenticationCode2=_totp_code(seed, counter + 1),
        )
        ctx.on_cleanup(lambda u=user, s=serial: _best_effort_deactivate(iam, u, s))

        enabled = iam.list_mfa_devices(UserName=user)["MFADevices"]
        assert any(d["SerialNumber"] == serial for d in enabled), (
            f"device {serial} not visible via the independent ListMFADevices read "
            f"after enabling with a code derived from its own seed"
        )


def _totp_code(base32_seed: str, counter: int) -> str:
    key = base64.b32decode(base32_seed, casefold=True)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code_int = (struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF) % 1_000_000
    return f"{code_int:06d}"


def _clock_offset(iam) -> float:
    """Estimated (AWS server time - local time) in seconds, from the Date header.

    TOTP codes are valid only within a ~30 s window, so the counter follows AWS's clock.
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
