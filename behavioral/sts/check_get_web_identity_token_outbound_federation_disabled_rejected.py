"""get-web-identity-token-outbound-federation-disabled-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-web-identity-token-outbound-federation-disabled-rejected"
GROUP = "error-semantics"
SERVICES = ["sts"]

# What _refusal returns when the call SUCCEEDS: an object no (code, message) pair can equal,
# so a poll waiting for a refusal keeps waiting and then fails on its deadline.
_SUCCEEDED = object()


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:iam-outbound-web-identity-federation")
def run(ctx) -> None:
    """GetWebIdentityToken is rejected while outbound web identity federation is disabled,
    and the identical call succeeds once the account-level feature is enabled.
    """
    iam = ctx.client("iam")
    sts = ctx.client("sts")

    original_enabled = _federation_enabled(iam)
    ctx.on_cleanup(lambda: _set_federation_enabled(iam, original_enabled))

    audience = [f"https://{ctx.unique_name('sim2real-owidt-aud-')}.example.com"]

    # Break exactly one thing: disable outbound federation for the account.
    _set_federation_enabled(iam, False)

    # Disabling may take a moment to propagate; poll until GetWebIdentityToken
    # consistently rejects with the expected code.
    refusal = _poll_settled(
        lambda: _refusal(
            lambda: sts.get_web_identity_token(Audience=audience, SigningAlgorithm="RS256")
        ),
        lambda r: r is not _SUCCEEDED,
    )
    code, message = refusal
    assert code == "OutboundWebIdentityFederationDisabledException", (
        f"expected OutboundWebIdentityFederationDisabledException while the feature is "
        f"disabled, got {code!r}"
    )
    expected_message = "OutboundWebIdentityFederation is disabled."
    assert message == expected_message, (
        f"expected the refusal message {expected_message!r}, got {message!r}"
    )

    # Effect absent: disabled state persists, and a repeat call still fails the
    # same way (no token was ever minted while disabled).
    assert _federation_enabled(iam) is False, (
        "expected JwtVendingEnabled=False (read independently via "
        "GetOutboundWebIdentityFederationInfo) to persist after the rejection"
    )
    again = _refusal(
        lambda: sts.get_web_identity_token(Audience=audience, SigningAlgorithm="RS256")
    )
    assert again == (code, expected_message), (
        f"expected the identical call to keep failing the same way while still disabled, "
        f"got {again!r}"
    )

    # Positive control: removing the one blocking condition (re-enabling the
    # feature) lets the identical call succeed. Re-enabling can also take a
    # moment to propagate.
    _set_federation_enabled(iam, True)
    resp = _poll_until(
        lambda: _try_get_token(sts, audience),
        lambda r: r is not None,
        timeout_s=30.0,
        interval_s=2.0,
    )
    assert resp["WebIdentityToken"], (
        f"expected a non-empty WebIdentityToken once re-enabled, got {resp.get('WebIdentityToken')!r}"
    )
    assert "Expiration" in resp, f"expected an Expiration field on the token response, got keys {list(resp)}"


def _refusal(fn):
    """The (code, message) of a refused call, or _SUCCEEDED when the call succeeds."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    return _SUCCEEDED


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
