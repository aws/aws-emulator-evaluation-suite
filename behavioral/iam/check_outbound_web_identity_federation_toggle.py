"""outbound-web-identity-federation-toggle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "outbound-web-identity-federation-toggle"
GROUP = "server-side"
SERVICES = ["iam"]



@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:iam-outbound-web-identity-federation")
def run(ctx) -> None:
    """Enable/DisableOutboundWebIdentityFederation flips a durable per-account server-side flag
    whose state is authoritatively readable via GetOutboundWebIdentityFederationInfo, and the
    enable/disable calls are idempotency-guarded (FeatureEnabled/FeatureDisabled)."""
    iam = ctx.client("iam")
    account = ctx.client("sts").get_caller_identity()["Account"]
    enabled_message = f"Outbound identity federation is already enabled for account {account}"
    disabled_message = f"Outbound identity federation is already disabled for account {account}"

    initially_enabled, info = _get_info(iam)

    if not initially_enabled:
        enable_resp = iam.enable_outbound_web_identity_federation()
        issuer = enable_resp["IssuerIdentifier"]
        assert issuer.startswith("https://") and issuer, (
            f"expected a non-empty https issuer URL from Enable, got {issuer!r}"
        )
        ctx.on_cleanup(lambda: _safe_disable(iam))

        ok, info2 = _get_info(iam)
        assert ok is True, "expected GetOutboundWebIdentityFederationInfo to succeed once enabled"
        assert info2["JwtVendingEnabled"] is True, (
            f"expected JwtVendingEnabled=True once enabled, got {info2}"
        )
        assert info2["IssuerIdentifier"] == issuer, (
            f"expected GetInfo's IssuerIdentifier to match Enable's, got "
            f"{info2['IssuerIdentifier']!r} vs {issuer!r}"
        )

        # Re-enabling while already enabled is rejected, not silently accepted.
        conflict_code, conflict_message = _error_code(
            lambda: iam.enable_outbound_web_identity_federation()
        )
        assert conflict_code == "FeatureEnabled", (
            f"expected FeatureEnabled on a redundant Enable, got {conflict_code!r}"
        )
        assert conflict_message == enabled_message, (
            f"expected message {enabled_message!r}, got {conflict_message!r}"
        )

        iam.disable_outbound_web_identity_federation()

        # Symmetric idempotency guard: a redundant Disable is rejected too, not silently
        # accepted -- the docstring's "FeatureEnabled/FeatureDisabled" claim covers both.
        disable_conflict_code, disable_conflict_message = _error_code(
            lambda: iam.disable_outbound_web_identity_federation()
        )
        assert disable_conflict_code == "FeatureDisabled", (
            f"expected FeatureDisabled on a redundant Disable, got {disable_conflict_code!r}"
        )
        assert disable_conflict_message == disabled_message, (
            f"expected message {disabled_message!r}, got {disable_conflict_message!r}"
        )

        ok3, _ = _get_info(iam)
        assert ok3 is False, (
            "expected GetOutboundWebIdentityFederationInfo to report disabled after Disable"
        )
    else:
        # Feature was already enabled by prior account activity; verify the conflict path
        # without tearing down a pre-existing account configuration.
        conflict_code, conflict_message = _error_code(
            lambda: iam.enable_outbound_web_identity_federation()
        )
        assert conflict_code == "FeatureEnabled", (
            f"expected FeatureEnabled on a redundant Enable of an already-enabled account, "
            f"got {conflict_code!r}"
        )
        assert conflict_message == enabled_message, (
            f"expected message {enabled_message!r}, got {conflict_message!r}"
        )
        assert info["JwtVendingEnabled"] is True, f"expected JwtVendingEnabled=True, got {info}"
        assert info["IssuerIdentifier"], (
            "expected a non-empty IssuerIdentifier from the initial GetInfo read"
        )


# ===== helpers =====
def _error_code(fn):
    """Call fn(); return its (error code, error message). An unexpected SUCCESS raises: a target
    accepting what real AWS refuses must not read as a mere code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _get_info(iam):
    try:
        resp = iam.get_outbound_web_identity_federation_info()
        return True, resp
    except ClientError as e:
        if e.response["Error"]["Code"] == "FeatureDisabled":
            return False, None
        raise


def _safe_disable(iam):
    try:
        iam.disable_outbound_web_identity_federation()
    except ClientError as e:
        if e.response["Error"]["Code"] != "FeatureDisabled":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
