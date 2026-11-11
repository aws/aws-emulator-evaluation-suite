"""get-web-identity-token-payload-size-exceeded-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-web-identity-token-payload-size-exceeded-rejected"
GROUP = "error-semantics"
SERVICES = ["sts"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control", "resource:account-singleton:iam-outbound-web-identity-federation")
def run(ctx) -> None:
    """Requesting a JWT payload beyond the service limit (via 50 maximally-sized
    session tags) raises JWTPayloadSizeExceededException, and the same call
    succeeds once the oversized tags are removed.
    """
    iam = ctx.client("iam")
    sts = ctx.client("sts")

    original_enabled = _federation_enabled(iam)
    ctx.on_cleanup(lambda: _set_federation_enabled(iam, original_enabled))
    _set_federation_enabled(iam, True)

    audience = [f"https://{ctx.unique_name('sim2real-jwtsz-aud-')}.example.com"]

    # Enabling federation can take a moment to propagate; poll a plain call
    # until it stops bouncing with "disabled" before exercising the oversized
    # payload path.
    _poll_settled(lambda: _try_get_token(sts, audience), lambda r: r is not None)

    # Break exactly one thing: request 50 tags at their maximum key/value size
    # (128 + 256 chars each => ~19KB of custom-claim material), which pushes the
    # signed JWT payload past the service's maximum token size.
    huge_tags = [
        {"Key": f"k{i:03d}" + ("x" * 121), "Value": "v" * 256} for i in range(50)
    ]
    code, message = _refusal(
        lambda: sts.get_web_identity_token(
            Audience=audience, SigningAlgorithm="RS256", Tags=huge_tags
        )
    )
    assert code == "JWTPayloadSizeExceededException", f"got {code!r}"
    expected_message = "JWT payload exceeds maximum allowed size"
    assert message == expected_message, (
        f"expected the refusal message {expected_message!r}, got {message!r}"
    )

    # Effect absent: no token was minted for the oversized request; retrying the
    # exact same oversized request still fails the same way.
    again = _refusal(
        lambda: sts.get_web_identity_token(
            Audience=audience, SigningAlgorithm="RS256", Tags=huge_tags
        )
    )
    assert again == (code, expected_message), f"got {again!r}"

    # Positive control: same audience/algorithm, but remove the oversized tags
    # (the one blocking condition) -- the call now succeeds.
    resp = _poll_settled(lambda: _try_get_token(sts, audience), lambda r: r is not None, times=1)
    assert resp["WebIdentityToken"], f"expected a WebIdentityToken, got {resp!r}"
    assert "Expiration" in resp, f"expected Expiration in response, got {resp!r}"


def _refusal(fn):
    """The (code, message) of a refused call; raises when the call succeeds."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it SUCCEEDED: {result!r}")


def _poll_settled(probe, predicate, *, times: int = 3, timeout_s: float = 60.0,
                  interval_s: float = 2.0):
    """The last of `times` CONSECUTIVE probe results that satisfy predicate. The account-level
    federation flag reaches STS replicas unevenly, so one observation does not mean it settled."""
    deadline = time.monotonic() + timeout_s
    streak, last = 0, None
    while True:
        last = probe()
        streak = streak + 1 if predicate(last) else 0
        if streak >= times:
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"no {times} consecutive matching results within {timeout_s}s (last={last!r})"
            )
        time.sleep(interval_s)


def _try_get_token(sts, audience):
    try:
        return sts.get_web_identity_token(Audience=audience, SigningAlgorithm="RS256")
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
