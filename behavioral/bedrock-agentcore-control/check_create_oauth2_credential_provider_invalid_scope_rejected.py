"""create-oauth2-credential-provider-invalid-scope-rejected."""
from __future__ import annotations

import re

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-oauth2-credential-provider-invalid-scope-rejected"
GROUP = "overly-permissive"
SERVICES = ["bedrock-agentcore-control"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateOauth2CredentialProvider with vendor GoogleOauth2 but a customOauth2ProviderConfig is refused with
    ValidationException "Provided configuration does not match selected type: GoogleOauth2" and creates nothing; a
    CustomOauth2 provider with a matching config is created and reads back as CustomOauth2."""
    bac = ctx.client("bedrock-agentcore-control")

    mismatched_name = _alnum(ctx, "s2rOauthBad", 128)
    code, message = _error_detail(
        lambda: bac.create_oauth2_credential_provider(
            name=mismatched_name,
            credentialProviderVendor="GoogleOauth2",
            oauth2ProviderConfigInput={
                "customOauth2ProviderConfig": {
                    "oauthDiscovery": {
                        "discoveryUrl": "https://example.com/.well-known/openid-configuration"
                    }
                }
            },
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected = "Provided configuration does not match selected type: GoogleOauth2"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the mismatched provider was never created.
    listed = bac.list_oauth2_credential_providers()
    names = {p["name"] for p in listed.get("credentialProviders", [])}
    assert mismatched_name not in names, "a vendor/config-mismatched provider should not exist"

    # Positive control: a config that matches its declared vendor is accepted.
    matched_name = _alnum(ctx, "s2rOauthOk", 128)
    created = bac.create_oauth2_credential_provider(
        name=matched_name,
        credentialProviderVendor="CustomOauth2",
        oauth2ProviderConfigInput={
            "customOauth2ProviderConfig": {
                "clientId": "sim2real-test-client-id",
                "clientSecret": "sim2real-test-client-secret",
                "oauthDiscovery": {
                    "discoveryUrl": "https://example.com/.well-known/openid-configuration"
                },
            }
        },
        tags={"sim2real-check": CHECK},
    )
    ctx.on_cleanup(lambda: _safe(lambda: bac.delete_oauth2_credential_provider(name=matched_name)))
    assert created["name"] == matched_name
    fetched = bac.get_oauth2_credential_provider(name=matched_name)
    assert fetched["credentialProviderVendor"] == "CustomOauth2"


def _alnum(ctx, prefix: str, maxlen: int) -> str:
    raw = ctx.unique_name(prefix)
    name = re.sub(r"[^A-Za-z0-9]", "", raw)
    return name[:maxlen]


def _error_detail(fn):
    """Return (code, message) of the ClientError fn raises; a success raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
