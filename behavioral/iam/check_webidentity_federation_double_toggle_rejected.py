"""webidentity-federation-double-toggle-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "webidentity-federation-double-toggle-rejected"
GROUP = 'errors'
SERVICES = ['iam']


_MSG_FEATURE_ENABLED = "Outbound identity federation is already enabled for account {account}"
_MSG_FEATURE_DISABLED_READ = "Outbound identity federation is disabled for account {account}"
_MSG_FEATURE_DISABLED = "Outbound identity federation is already disabled for account {account}"


def _rejected(fn, description):
    """The ClientError's Error dict from fn(); an unexpected success fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected {description} to be rejected, but it SUCCEEDED: {result!r}")


def _assert_error(err, code, message):
    assert err.get("Code") == code, f"expected {code}, got {err!r}"
    assert err.get("Message") == message, (err.get("Message"), message)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:iam-outbound-web-identity-federation")
def run(ctx) -> None:
    """A redundant Enable/DisableOutboundWebIdentityFederation is rejected FeatureEnabled /
    FeatureDisabled with no effect on GetOutboundWebIdentityFederationInfo; the original state
    of this account-wide setting is restored."""
    iam = ctx.client("iam")
    account = ctx.client("sts").get_caller_identity()["Account"]
    # Probe: a bare success (feature was disabled) and FeatureEnabled are both legitimate here.
    try:
        iam.enable_outbound_web_identity_federation()
        originally_enabled = False
    except ClientError as exc:
        enable_code = exc.response.get("Error", {}).get("Code")
        assert enable_code == "FeatureEnabled", (
            f"unexpected error enabling outbound web identity federation: {enable_code}"
        )
        enable_message = exc.response.get("Error", {}).get("Message")
        expected = _MSG_FEATURE_ENABLED.format(account=account)
        assert enable_message == expected, f"expected message {expected!r}, got {enable_message!r}"
        originally_enabled = True

    def _restore():
        if not originally_enabled:
            try:
                iam.disable_outbound_web_identity_federation()
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") != "FeatureDisabled":
                    raise

    ctx.on_cleanup(_restore)

    # The feature is now enabled either way.
    err_double_enable = _rejected(
        lambda: iam.enable_outbound_web_identity_federation(), "a redundant Enable"
    )
    _assert_error(err_double_enable, "FeatureEnabled", _MSG_FEATURE_ENABLED.format(account=account))
    info_after_double_enable = iam.get_outbound_web_identity_federation_info()
    assert info_after_double_enable.get("JwtVendingEnabled") is True, (
        f"expected JwtVendingEnabled=True after a rejected redundant Enable, "
        f"got {info_after_double_enable}"
    )

    # While disabled, the info read itself fails with FeatureDisabled.
    iam.disable_outbound_web_identity_federation()
    err_after_disable = _rejected(
        lambda: iam.get_outbound_web_identity_federation_info(), "a read right after Disable"
    )
    _assert_error(err_after_disable, "FeatureDisabled", _MSG_FEATURE_DISABLED_READ.format(account=account))

    err_double_disable = _rejected(
        lambda: iam.disable_outbound_web_identity_federation(), "a redundant Disable"
    )
    _assert_error(err_double_disable, "FeatureDisabled", _MSG_FEATURE_DISABLED.format(account=account))
    err_after_double_disable = _rejected(
        lambda: iam.get_outbound_web_identity_federation_info(),
        "a read after a rejected redundant Disable",
    )
    _assert_error(err_after_double_disable, "FeatureDisabled", _MSG_FEATURE_DISABLED_READ.format(account=account))

    # Re-enable so `_restore` (which only disables) returns the account to its original state.
    restore_resp = iam.enable_outbound_web_identity_federation()
    restore_issuer = restore_resp.get("IssuerIdentifier")
    assert restore_issuer and restore_issuer.startswith("https://"), (
        f"bad IssuerIdentifier on restore-enable: {restore_issuer!r}"
    )
    info_final = iam.get_outbound_web_identity_federation_info()
    assert (
        info_final.get("JwtVendingEnabled") is True
        and info_final.get("IssuerIdentifier") == restore_issuer
    ), f"expected the restore-enable to be independently observable, got {info_final}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
