"""get-outbound-web-identity-federation-info-contract."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-outbound-web-identity-federation-info-contract"
GROUP = "error-semantics"
SERVICES = ["iam"]



@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:iam-outbound-web-identity-federation")
def run(ctx) -> None:
    """GetOutboundWebIdentityFederationInfo returns JwtVendingEnabled and an issuer when enabled and
    FeatureDisabled when disabled; the account's original state is restored and re-read."""
    iam = ctx.client("iam")
    feature_disabled_message = f"Outbound identity federation is disabled for account {ctx.account}"

    try:
        initial = iam.get_outbound_web_identity_federation_info()
        initially_enabled = True
    except AttributeError:
        raise AssertionError("GetOutboundWebIdentityFederationInfo not available in installed SDK")
    except Exception as exc:  # noqa: BLE001
        code = _error_code_from_exc(exc)
        if code != "FeatureDisabled":
            raise AssertionError(f"GetOutboundWebIdentityFederationInfo unavailable: {exc}")
        initial = None
        initially_enabled = False

    if initially_enabled:
        assert isinstance(initial.get("JwtVendingEnabled"), bool), (
            f"expected JwtVendingEnabled to be a bool, got {initial.get('JwtVendingEnabled')!r}"
        )
        assert initial["JwtVendingEnabled"] is True, (
            f"expected JwtVendingEnabled=True while enabled, got {initial['JwtVendingEnabled']!r}"
        )
        assert isinstance(initial.get("IssuerIdentifier"), str) and initial["IssuerIdentifier"], (
            f"expected a non-empty IssuerIdentifier while enabled, got {initial.get('IssuerIdentifier')!r}"
        )

        iam.disable_outbound_web_identity_federation()
        ctx.on_cleanup(lambda: _safe_enable(iam))
        code, message = _error(lambda: iam.get_outbound_web_identity_federation_info())
        assert code == "FeatureDisabled", f"expected FeatureDisabled once disabled, got {code}"
        assert message == feature_disabled_message, (
            f"expected message {feature_disabled_message!r}, got {message!r}"
        )

        restored = iam.enable_outbound_web_identity_federation()
        restored_issuer = restored.get("IssuerIdentifier")
        assert restored_issuer and restored_issuer.startswith("https://"), (
            f"expected a non-empty https IssuerIdentifier on re-enable, got {restored_issuer!r}"
        )
        final = iam.get_outbound_web_identity_federation_info()
        assert final["JwtVendingEnabled"] is True, (
            f"expected JwtVendingEnabled=True after restoring, got {final['JwtVendingEnabled']!r}"
        )
    else:
        enabled = iam.enable_outbound_web_identity_federation()
        ctx.on_cleanup(lambda: _safe_disable(iam))
        issuer = enabled.get("IssuerIdentifier")
        assert issuer and issuer.startswith("https://"), (
            f"expected a non-empty https IssuerIdentifier on enable, got {issuer!r}"
        )
        resp = iam.get_outbound_web_identity_federation_info()
        assert resp["JwtVendingEnabled"] is True, (
            f"expected JwtVendingEnabled=True once enabled, got {resp['JwtVendingEnabled']!r}"
        )
        assert isinstance(resp.get("IssuerIdentifier"), str) and resp["IssuerIdentifier"], (
            f"expected a non-empty IssuerIdentifier once enabled, got {resp.get('IssuerIdentifier')!r}"
        )

        iam.disable_outbound_web_identity_federation()
        restored_code, message = _error(lambda: iam.get_outbound_web_identity_federation_info())
        assert restored_code == "FeatureDisabled", (
            "expected FeatureDisabled after restoring to the original disabled state, "
            f"got {restored_code}"
        )
        assert message == feature_disabled_message, (
            f"expected message {feature_disabled_message!r}, got {message!r}"
        )


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


def _error_code_from_exc(exc):
    from botocore.exceptions import ClientError

    if isinstance(exc, ClientError):
        return exc.response["Error"]["Code"]
    return None


def _safe_enable(iam):
    from botocore.exceptions import ClientError

    try:
        iam.enable_outbound_web_identity_federation()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "FeatureEnabled":
            raise


def _safe_disable(iam):
    from botocore.exceptions import ClientError

    try:
        iam.disable_outbound_web_identity_federation()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "FeatureDisabled":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
