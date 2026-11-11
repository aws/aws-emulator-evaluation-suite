"""op-contract-disableOutboundWebIdentityFederation."""
from __future__ import annotations


from behavioral_harness import tags

CHECK = "op-contract-disableOutboundWebIdentityFederation"
GROUP = "error-semantics"
SERVICES = ["iam"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:iam-outbound-web-identity-federation")
def run(ctx) -> None:
    """DisableOutboundWebIdentityFederation leaves the feature disabled, read
    back by GetOutboundWebIdentityFederationInfo, and repeated disables fail
    with FeatureDisabled and its exact message."""
    iam = ctx.client("iam")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    already_disabled = f"Outbound identity federation is already disabled for account {account_id}"

    original_enabled = _is_owif_enabled(ctx)

    if original_enabled:
        # Currently enabled: disabling should succeed once...
        ctx.on_cleanup(lambda: iam.enable_outbound_web_identity_federation())
        iam.disable_outbound_web_identity_federation()
        # ...and the destination must independently read it as disabled...
        assert not _is_owif_enabled(ctx), (
            "expected the feature to read as disabled after Disable succeeded"
        )
        # ...and a second disable on the now-disabled account must reject.
        code, message = _error(lambda: iam.disable_outbound_web_identity_federation())
        assert code == "FeatureDisabled", f"expected FeatureDisabled, got {code!r}"
        assert message == already_disabled, f"expected message {already_disabled!r}, got {message!r}"
    else:
        # Currently disabled: disabling again must reject immediately.
        code, message = _error(lambda: iam.disable_outbound_web_identity_federation())
        assert code == "FeatureDisabled", f"expected FeatureDisabled, got {code!r}"
        assert message == already_disabled, f"expected message {already_disabled!r}, got {message!r}"
        # Demonstrate the success-path contract too: enable, then disable
        # successfully, restoring the original disabled state.
        iam.enable_outbound_web_identity_federation()
        iam.disable_outbound_web_identity_federation()
        assert not _is_owif_enabled(ctx), (
            "expected the feature to read as disabled after the restoring Disable"
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
