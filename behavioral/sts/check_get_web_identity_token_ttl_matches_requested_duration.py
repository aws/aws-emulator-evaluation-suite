"""get-web-identity-token-ttl-matches-requested-duration."""
from __future__ import annotations

import base64
import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-web-identity-token-ttl-matches-requested-duration"
GROUP = "visibility-timeout-ttl"
SERVICES = ["sts"]


@tags("axis:happy-path", "cap:c4", "cap:c7", "concern:representation", "plane:control", "resource:account-singleton:iam-outbound-web-identity-federation")
def run(ctx: Any) -> None:
    """The exp-iat TTL embedded in a GetWebIdentityToken JWT matches the
    caller-requested DurationSeconds exactly, and the structured Expiration field
    returned alongside it agrees with the JWT's own exp claim."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")

    # Outbound web-identity federation is an account-level flag GetWebIdentityToken
    # requires; create-or-adopt it as a prerequisite instead of failing when a fresh
    # account starts with it off, and restore whatever state we found.
    original_enabled = _federation_enabled(iam)
    ctx.on_cleanup(lambda: _set_federation_enabled(iam, original_enabled))
    _set_federation_enabled(iam, True)

    requested_duration = 120
    audience = [f"https://{ctx.unique_name('sim2real-wit-ttl-')}.example.com"]

    # Enabling federation can take a moment to propagate; poll the exact call under
    # test until it stops bouncing with "disabled".
    resp = _poll_until(
        lambda: _try_get_token(sts, audience, requested_duration),
        lambda r: r is not None,
        timeout_s=30.0,
        interval_s=2.0,
    )

    token = resp["WebIdentityToken"]
    payload = _decode_jwt_payload(token)
    actual_ttl = payload["exp"] - payload["iat"]
    assert actual_ttl == requested_duration, (
        f"expected exp-iat TTL {requested_duration}, got {actual_ttl} "
        f"(iat={payload['iat']}, exp={payload['exp']})"
    )

    expiration_ts = resp["Expiration"].timestamp()
    assert abs(expiration_ts - payload["exp"]) <= 1, (
        f"structured Expiration ({expiration_ts}) disagrees with JWT exp claim "
        f"({payload['exp']}) by more than 1s"
    )


def _decode_jwt_payload(token: str) -> dict:
    segment = token.split(".")[1]
    padded = segment + "=" * (-len(segment) % 4)
    return json.loads(base64.urlsafe_b64decode(padded))


def _federation_enabled(iam) -> bool:
    try:
        info = iam.get_outbound_web_identity_federation_info()
    except ClientError as e:
        if e.response["Error"]["Code"] == "FeatureDisabled":
            return False
        raise
    return bool(info.get("JwtVendingEnabled", False))


def _set_federation_enabled(iam, enabled: bool) -> None:
    current = _federation_enabled(iam)
    if enabled and not current:
        try:
            iam.enable_outbound_web_identity_federation()
        except ClientError as e:
            if e.response["Error"]["Code"] != "FeatureEnabled":
                raise
    elif not enabled and current:
        try:
            iam.disable_outbound_web_identity_federation()
        except ClientError as e:
            if e.response["Error"]["Code"] != "FeatureDisabled":
                raise


def _try_get_token(sts, audience, duration_seconds):
    try:
        return sts.get_web_identity_token(
            Audience=audience,
            SigningAlgorithm="RS256",
            DurationSeconds=duration_seconds,
        )
    except ClientError as e:
        if e.response["Error"]["Code"] == "OutboundWebIdentityFederationDisabledException":
            return None
        raise


def _poll_until(probe, predicate, timeout_s: float = 30.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result) and time.monotonic() < deadline:
        time.sleep(interval_s)
        result = probe()
    if not predicate(result):
        raise AssertionError("condition not met within timeout")
    return result


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
