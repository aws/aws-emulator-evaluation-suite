"""get-session-token-invalid-mfa-code-rejected."""
from __future__ import annotations

import base64
import hashlib
import hmac
import struct
import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "get-session-token-invalid-mfa-code-rejected"
GROUP = "error-semantics"
SERVICES = ["sts"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx: Any) -> None:
    """GetSessionToken with a SerialNumber for a real, enabled virtual MFA device
    but an incorrect TokenCode is denied with AccessDenied and issues no
    credentials, while the same call with a correctly-computed TokenCode succeeds."""
    iam = ctx.client("iam")
    user_name = ctx.unique_name("sim2real-behav-mfauser-")
    iam.create_user(UserName=user_name, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    device_name = ctx.unique_name("sim2real-behav-mfadev-")
    device = iam.create_virtual_mfa_device(
        VirtualMFADeviceName=device_name,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["VirtualMFADevice"]
    serial = device["SerialNumber"]
    seed_b32 = device["Base32StringSeed"]
    if isinstance(seed_b32, bytes):
        seed_b32 = seed_b32.decode()

    ctx.on_cleanup(
        lambda: _ignore_no_such_entity(
            lambda: iam.delete_virtual_mfa_device(SerialNumber=serial)
        )
    )

    # Codes are computed early in a TOTP window so they are still current when IAM checks them.
    _wait_for_window_headroom()
    now = time.time()
    iam.enable_mfa_device(
        UserName=user_name,
        SerialNumber=serial,
        AuthenticationCode1=_totp(seed_b32, now),
        AuthenticationCode2=_totp(seed_b32, now + 30),
    )
    ctx.on_cleanup(
        lambda: _ignore_no_such_entity(
            lambda: iam.deactivate_mfa_device(UserName=user_name, SerialNumber=serial)
        )
    )

    key = iam.create_access_key(UserName=user_name)["AccessKey"]
    key_id = key["AccessKeyId"]
    ctx.on_cleanup(
        lambda: _ignore_no_such_entity(
            lambda: iam.delete_access_key(UserName=user_name, AccessKeyId=key_id)
        )
    )
    creds = {"AccessKeyId": key_id, "SecretAccessKey": key["SecretAccessKey"]}
    client = _client_with_creds(ctx, "sts", creds)
    _retry_until_success(lambda: client.get_caller_identity(), timeout_s=30.0, interval_s=2.0)

    wrong_code = "000000"
    real_code_now = _totp(seed_b32, time.time())
    if wrong_code == real_code_now:
        wrong_code = "111111"

    result = {"credentials_issued": False}

    def _try_wrong() -> str | None:
        from botocore.exceptions import ClientError

        try:
            client.get_session_token(SerialNumber=serial, TokenCode=wrong_code)
            result["credentials_issued"] = True
            return "UNEXPECTED_SUCCESS", None
        except ClientError as exc:
            return exc.response["Error"]["Code"], exc.response["Error"].get("Message")

    code, message = _retry_until(
        _try_wrong,
        predicate=lambda r: r[0] is not None,
        timeout_s=30.0,
        interval_s=3.0,
    )
    assert code == "AccessDenied", (
        f"GetSessionToken with an incorrect TokenCode should be denied with "
        f"AccessDenied, got {code!r}"
    )
    # AWS's message carries a trailing space.
    expected_message = "MultiFactorAuthentication failed with invalid MFA one time pass code. "
    assert message == expected_message, (
        f"expected the refusal message {expected_message!r}, got {message!r}"
    )
    assert result["credentials_issued"] is False, (
        "GetSessionToken with an incorrect TokenCode must not issue credentials"
    )

    # Positive control: a correctly-computed current TokenCode for the same,
    # still-enabled device succeeds and issues real, usable credentials.
    good_resp = _session_token_with_live_code(ctx, client, serial, seed_b32)
    session_creds = good_resp["Credentials"]
    assert "AccessKeyId" in session_creds, (
        f"GetSessionToken with a correct TokenCode returned no credentials: {good_resp}"
    )

    # Independent read at the destination: the issued session credentials must
    # actually resolve to this user, through a different STS operation than the
    # one that minted them.
    session_client = _client_with_creds(ctx, "sts", session_creds)
    identity = session_client.get_caller_identity()
    assert identity["Arn"].endswith(f"user/{user_name}"), (
        f"session-token credentials from the correct TokenCode did not resolve "
        f"to {user_name}: {identity['Arn']}"
    )


def _totp(base32_secret: str, for_time: float, digits: int = 6, step: int = 30) -> str:
    padding = "=" * ((8 - len(base32_secret) % 8) % 8)
    key = base64.b32decode(base32_secret.upper() + padding)
    counter = int(for_time // step)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code_int = (struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF) % (
        10 ** digits
    )
    return str(code_int).zfill(digits)


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _wait_for_window_headroom(min_left_s: float = 5.0, step: int = 30) -> None:
    """Return once at least min_left_s seconds remain in the current TOTP window."""
    deadline = time.monotonic() + min_left_s + 2.0
    while step - (time.time() % step) < min_left_s and time.monotonic() < deadline:
        time.sleep(1.0)


def _session_token_with_live_code(ctx: Any, client: Any, serial: str, seed_b32: str) -> dict:
    """GetSessionToken with the current TOTP code; a refusal is retried with the next window's
    code, so a code that crossed a window boundary in flight does not decide the verdict."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + _budget_s(ctx, 40.0)
    refused: set[str] = set()
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        _wait_for_window_headroom()
        code = _totp(seed_b32, time.time())
        if code in refused:
            time.sleep(1.0)
            continue
        try:
            return client.get_session_token(SerialNumber=serial, TokenCode=code)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDenied":
                raise
            refused.add(code)
            last_exc = exc
    if _budget_spent(ctx):
        raise TimeoutError("GetSessionToken accepting a live TOTP code: the run budget ended first; not graded")
    raise AssertionError(
        f"GetSessionToken with a correctly-computed TokenCode was refused: {last_exc}"
    )


def _ignore_no_such_entity(fn: Callable[[], Any]) -> None:
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _client_with_creds(ctx: Any, service: str, creds: dict) -> Any:
    return ctx.client(service, creds={
        "aws_access_key_id": creds["AccessKeyId"],
        "aws_secret_access_key": creds["SecretAccessKey"],
        "aws_session_token": creds.get("SessionToken"),
    })


def _retry_until_success(
    fn: Callable[[], Any], *, timeout_s: float, interval_s: float
) -> Any:
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"operation never succeeded within {timeout_s}s: {last_exc}")


def _retry_until(
    fn: Callable[[], Any], *, predicate: Callable[[Any], bool], timeout_s: float, interval_s: float
) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = fn()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
