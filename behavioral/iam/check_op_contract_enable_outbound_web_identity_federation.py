"""op-contract-enableOutboundWebIdentityFederation."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-enableOutboundWebIdentityFederation"
GROUP = "error-semantics"
SERVICES = ["iam"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:iam-outbound-web-identity-federation")
def run(ctx) -> None:
    """EnableOutboundWebIdentityFederation returns a real issuer URL on success
    and rejects a repeat enable of an already-enabled account with
    FeatureEnabled, regardless of the account's starting state."""
    iam = ctx.client("iam")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    already_enabled = f"Outbound identity federation is already enabled for account {account_id}"

    original_enabled = _is_owif_enabled(ctx)

    if original_enabled:
        # Already enabled: enabling again must reject immediately.
        code, message = _error(lambda: iam.enable_outbound_web_identity_federation())
        assert code == "FeatureEnabled", f"expected FeatureEnabled, got {code!r}"
        assert message == already_enabled, f"expected message {already_enabled!r}, got {message!r}"
        info = iam.get_outbound_web_identity_federation_info()
        assert info.get("IssuerIdentifier"), "expected a non-empty IssuerIdentifier"
    else:
        ctx.on_cleanup(lambda: iam.disable_outbound_web_identity_federation())
        resp = iam.enable_outbound_web_identity_federation()
        issuer = resp.get("IssuerIdentifier")
        assert issuer and issuer.startswith("https://"), f"bad IssuerIdentifier: {issuer!r}"
        # A second enable on the now-enabled account must reject.
        code, message = _error(lambda: iam.enable_outbound_web_identity_federation())
        assert code == "FeatureEnabled", f"expected FeatureEnabled, got {code!r}"
        assert message == already_enabled, f"expected message {already_enabled!r}, got {message!r}"
        # The rejected repeat enable must have had no effect: an independent read still
        # reports the same issuer the first (accepted) enable minted.
        info = iam.get_outbound_web_identity_federation_info()
        assert info.get("IssuerIdentifier") == issuer, (
            f"issuer changed after rejected repeat enable: {info.get('IssuerIdentifier')!r} != {issuer!r}"
        )


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its error (Code, Message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _is_owif_enabled(ctx) -> bool:
    from botocore.exceptions import ClientError

    iam = ctx.client("iam")
    try:
        iam.get_outbound_web_identity_federation_info()
        return True
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code == "FeatureDisabled":
            return False
        raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
