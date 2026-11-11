"""concurrent-resync-mfa-device-race-rejected."""
from __future__ import annotations

import base64
import hashlib
import hmac
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-resync-mfa-device-race-rejected"
GROUP = "concurrency"
SERVICES = ["iam"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Concurrent ResyncMFADevice calls with one code pair let exactly one through; losers get a
    concurrent-modification or invalid-code error, and the device stays with the user."""
    iam = ctx.client("iam")
    user_name = ctx.unique_name("sim2real-mfaresync-")
    device_name = ctx.unique_name("sim2real-mfaresync-dev-")

    iam.create_user(UserName=user_name, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    device = iam.create_virtual_mfa_device(
        VirtualMFADeviceName=device_name, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )["VirtualMFADevice"]
    serial = device["SerialNumber"]
    seed = device["Base32StringSeed"]
    ctx.on_cleanup(lambda: iam.delete_virtual_mfa_device(SerialNumber=serial))
    ctx.on_cleanup(lambda: iam.deactivate_mfa_device(UserName=user_name, SerialNumber=serial))

    code1, code2 = _consecutive_totp_codes(seed)
    iam.enable_mfa_device(
        UserName=user_name,
        SerialNumber=serial,
        AuthenticationCode1=code1,
        AuthenticationCode2=code2,
    )

    # AWS rejects reuse of a previously-submitted TOTP code (InvalidAuthenticationCode).
    # ResyncMFADevice exists specifically to correct clock drift, so give it codes from
    # a window that is offset from "now" (simulating a device running fast) rather than
    # the currently-valid window already consumed by EnableMFADevice above.
    racer_count = 6
    resync_code1, resync_code2 = _consecutive_totp_codes(seed, offset_seconds=90)
    barrier = threading.Barrier(racer_count)
    outcomes: list[str] = [""] * racer_count
    messages: dict[int, str] = {}

    def racer(i: int) -> None:
        barrier.wait()
        try:
            iam.resync_mfa_device(
                UserName=user_name,
                SerialNumber=serial,
                AuthenticationCode1=resync_code1,
                AuthenticationCode2=resync_code2,
            )
            outcomes[i] = "ok"
        except ClientError as exc:
            outcomes[i] = exc.response["Error"]["Code"]
            messages[i] = exc.response["Error"].get("Message", "")

    with ThreadPoolExecutor(max_workers=racer_count) as pool:
        list(pool.map(racer, range(racer_count)))

    successes = [o for o in outcomes if o == "ok"]
    failures = [o for o in outcomes if o != "ok"]

    # On real AWS, the losing side of the race is rejected either as an explicit
    # optimistic-lock conflict (ConcurrentModificationException) or because the first
    # winner's successful resync advances the device's internal counter state, making
    # the (now stale) authentication codes used by the other racers no longer valid
    # (InvalidAuthenticationCodeException). Either way, no racer silently corrupts
    # state -- it is rejected outright.
    acceptable_failure_codes = {
        "ConcurrentModificationException",
        "ConcurrentModification",
        "InvalidAuthenticationCodeException",
        "InvalidAuthenticationCode",
    }
    for code in failures:
        assert code in acceptable_failure_codes, (
            f"unexpected losing-racer error code {code!r} (expected "
            f"ConcurrentModificationException or InvalidAuthenticationCodeException)"
        )
    # The exact wording AWS returns for each losing-racer refusal.
    worded = {
        "ConcurrentModification": (
            "There is an intent for this identifier already. Another request is modifying the "
            f"TFA token for serial number {serial}."
        ),
        "InvalidAuthenticationCode": "Authentication code for device is not valid.",
    }
    for code, message in ((outcomes[i], m) for i, m in messages.items()):
        if code in worded:
            assert message == worded[code], f"{code} message {message!r}, expected {worded[code]!r}"
    # Every racer sends the identical code pair, so serialized access lets exactly one through;
    # "at least one" would also accept every racer silently succeeding.
    assert len(successes) == 1, (
        f"expected exactly one winning ResyncMFADevice call among {racer_count} racers "
        f"sharing the same code pair, got {len(successes)} successes: outcomes={outcomes!r}"
    )

    devices = iam.list_mfa_devices(UserName=user_name)["MFADevices"]
    assert any(d["SerialNumber"] == serial for d in devices), (
        "MFA device must remain associated with the user after concurrent resync attempts"
    )


def _totp_code(base32_secret: str, for_time: float, digits: int = 6, interval: int = 30) -> str:
    key = base64.b32decode(base32_secret, casefold=True)
    counter = int(for_time // interval)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code_int = (struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF) % (10**digits)
    return str(code_int).zfill(digits)


def _consecutive_totp_codes(base32_secret: str, offset_seconds: float = 0.0) -> tuple[str, str]:
    now = time.time() + offset_seconds
    return _totp_code(base32_secret, now), _totp_code(base32_secret, now + 30)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
