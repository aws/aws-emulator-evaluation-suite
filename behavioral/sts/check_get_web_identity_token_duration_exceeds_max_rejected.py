"""get-web-identity-token-duration-exceeds-max-rejected."""
from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-web-identity-token-duration-exceeds-max-rejected"
GROUP = "error-semantics"
SERVICES = ["sts"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control", "resource:account-singleton:iam-outbound-web-identity-federation")
def run(ctx) -> None:
    """GetWebIdentityToken rejects DurationSeconds above the 3600s maximum with ValidationError
    and its exact message (not SessionDurationEscalationException), repeatably; 300s succeeds.
    """
    iam = ctx.client("iam")
    original_enabled = _federation_enabled(iam)
    ctx.on_cleanup(lambda: _set_federation_enabled(iam, original_enabled))
    _set_federation_enabled(iam, True)

    # botocore validates the 60-3600s range locally; disable that so the value is sent.
    sts = _client_no_validation(ctx, "sts")
    audience = [f"https://sim2real.invalid/{ctx.unique_name('aud')}"]

    # Positive control: an in-range duration succeeds. Enabling federation in IAM takes
    # several seconds to reach STS (OutboundWebIdentityFederationDisabledException meanwhile).
    ok = _poll_until(
        lambda: _try_get_token(sts, audience),
        lambda r: r is not None,
        timeout_s=30.0,
        interval_s=2.0,
    )
    assert ok["WebIdentityToken"], "positive control returned no WebIdentityToken"
    assert "Expiration" in ok, f"positive control response missing Expiration: {ok!r}"

    # Rejected as a range violation, not silently clamped.
    code, message = _refusal(
        lambda: sts.get_web_identity_token(
            Audience=audience, SigningAlgorithm="RS256", DurationSeconds=999999
        )
    )
    assert code == "ValidationError", f"expected ValidationError, got {code!r}"
    expected_message = (
        "1 validation error detected: Value '999999' at 'durationSeconds' failed to satisfy "
        "constraint: Member must have value less than or equal to 3600"
    )
    assert message == expected_message, (
        f"expected the refusal message {expected_message!r}, got {message!r}"
    )

    # Effect absent: repeating the same out-of-range request still fails the
    # same way -- no token was ever minted for it.
    code_again, message_again = _refusal(
        lambda: sts.get_web_identity_token(
            Audience=audience, SigningAlgorithm="RS256", DurationSeconds=999999
        )
    )
    assert code_again == "ValidationError", f"expected ValidationError, got {code_again!r}"
    assert message_again == expected_message, (
        f"expected the refusal message {expected_message!r}, got {message_again!r}"
    )


def _client_no_validation(ctx, service: str):
    return ctx.client(service, config=Config(parameter_validation=False))


def _try_get_token(sts, audience):
    try:
        return sts.get_web_identity_token(
            Audience=audience, SigningAlgorithm="RS256", DurationSeconds=300
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "OutboundWebIdentityFederationDisabledException":
            return None
        raise


def _poll_until(probe, predicate, timeout_s: float, interval_s: float):
    import time

    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result) and time.monotonic() < deadline:
        time.sleep(interval_s)
        result = probe()
    if not predicate(result):
        raise AssertionError(
            "outbound web identity federation was enabled but GetWebIdentityToken "
            f"never became effective within {timeout_s}s"
        )
    return result


def _refusal(fn):
    """The (code, message) of a refused call; raises when the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED: {result!r}")


def _federation_enabled(iam) -> bool:
    try:
        info = iam.get_outbound_web_identity_federation_info()
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "FeatureDisabled":
            return False
        raise
    return bool(info.get("JwtVendingEnabled", False))


def _set_federation_enabled(iam, enabled: bool) -> None:
    current = _federation_enabled(iam)
    if enabled and not current:
        try:
            iam.enable_outbound_web_identity_federation()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "FeatureEnabled":
                raise
    elif not enabled and current:
        try:
            iam.disable_outbound_web_identity_federation()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "FeatureDisabled":
                raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
