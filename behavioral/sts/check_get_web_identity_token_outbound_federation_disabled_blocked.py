"""get-web-identity-token-outbound-federation-disabled-blocked."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-web-identity-token-outbound-federation-disabled-blocked"
GROUP = "server-side"
SERVICES = ["sts"]

# What _refusal returns when the call SUCCEEDS: an object no (code, message) pair can equal,
# so a poll waiting for a refusal keeps waiting and then fails on its deadline.
_SUCCEEDED = object()


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:iam-outbound-web-identity-federation")
def run(ctx) -> None:
    """When outbound web-identity federation is disabled at the account level,
    GetWebIdentityToken is server-side blocked with OutboundWebIdentityFederationDisabledException
    regardless of the caller's own IAM permissions.
    """
    iam = ctx.client("iam")
    sts = ctx.client("sts")

    if not hasattr(iam, "disable_outbound_web_identity_federation") or not hasattr(
        sts, "get_web_identity_token"
    ):
        raise AssertionError(
            "Outbound web-identity federation (IAM DisableOutboundWebIdentityFederation / "
            "EnableOutboundWebIdentityFederation / STS GetWebIdentityToken) is a newly "
            "introduced control surface; this environment's boto3 build does not expose the "
            "required client methods to observe or control the feature flag."
        )

    audience = ["sim2real.example.com"]

    # Restore whatever state the account was in when we're done, regardless of which
    # branch below actually flips it.
    info = _federation_info(iam)
    was_enabled = bool(info.get("JwtVendingEnabled"))
    if was_enabled:
        ctx.on_cleanup(lambda: iam.enable_outbound_web_identity_federation())
    else:
        ctx.on_cleanup(lambda: _disable_idempotent(iam))

    _disable_idempotent(iam)

    # The disable is an account-level control-plane change; give it a bounded window to
    # take effect before asserting the data-plane rejection.
    disabled_info = _poll_until(
        lambda: _federation_info(iam),
        lambda i: bool(i.get("JwtVendingEnabled")) is False,
        timeout_s=60.0,
        interval_s=5.0,
    )
    # Effect absent, on an independent read: the control-plane's own account-level flag
    # agrees the feature is off, not just the data-plane call below.
    assert disabled_info.get("JwtVendingEnabled") is False, (
        f"account-level flag still reports enabled after disable: {disabled_info!r}"
    )

    refusal = _poll_until(
        lambda: _refusal(
            lambda: sts.get_web_identity_token(Audience=audience, SigningAlgorithm="RS256")
        ),
        lambda r: r is not _SUCCEEDED,
        timeout_s=60.0,
        interval_s=5.0,
    )
    code, message = refusal
    assert code == "OutboundWebIdentityFederationDisabledException", f"unexpected code: {code}"
    expected_message = "OutboundWebIdentityFederation is disabled."
    assert message == expected_message, (
        f"expected the refusal message {expected_message!r}, got {message!r}"
    )

    # Positive control: re-enabling makes issuance work again with the exact same caller
    # and audience, proving the denial above was the feature flag and not a broken request.
    iam.enable_outbound_web_identity_federation()
    enabled_info = _poll_until(
        lambda: _federation_info(iam),
        lambda i: bool(i.get("JwtVendingEnabled")) is True,
        timeout_s=60.0,
        interval_s=5.0,
    )
    assert enabled_info.get("JwtVendingEnabled") is True, (
        f"account-level flag still reports disabled after enable: {enabled_info!r}"
    )

    # Terminal read is the actual minted token, at the data plane the disable was blocking —
    # not just the absence of an error code.
    resp = _poll_until(
        lambda: _try_get_token(sts, audience),
        lambda r: r is not None,
        timeout_s=60.0,
        interval_s=5.0,
    )
    assert resp.get("WebIdentityToken"), f"no token minted once re-enabled: {resp!r}"
    assert "Expiration" in resp, f"no Expiration on minted token: {resp!r}"


# ===== helpers =====

def _federation_info(iam) -> dict:
    # Real AWS does not answer this read with JwtVendingEnabled=False when the feature is
    # off — it ERRORS with FeatureDisabled instead, so a plain call crashes on the common
    # (disabled) state rather than reporting it.
    try:
        return iam.get_outbound_web_identity_federation_info()
    except ClientError as exc:
        if exc.response["Error"]["Code"] in ("FeatureDisabled", "FeatureDisabledException"):
            return {"JwtVendingEnabled": False}
        raise


def _disable_idempotent(iam) -> None:
    try:
        iam.disable_outbound_web_identity_federation()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "OutboundWebIdentityFederationAlreadyDisabledException",
            "InvalidRequestException",
            "FeatureDisabled",
            "FeatureDisabledException",
        ):
            raise


def _poll_until(probe, predicate, timeout_s: float, interval_s: float):
    import time

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if not predicate(last):
        raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")
    return last


def _refusal(fn):
    """The (code, message) of a refused call, or _SUCCEEDED when the call succeeds."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    return _SUCCEEDED


def _try_get_token(sts, audience):
    try:
        return sts.get_web_identity_token(Audience=audience, SigningAlgorithm="RS256")
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "OutboundWebIdentityFederationDisabledException":
            return None
        raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
