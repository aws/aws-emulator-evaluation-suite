"""credential-provider-type-isolation-get-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "credential-provider-type-isolation-get-rejected"
GROUP = "overly-permissive"
SERVICES = ["bedrock-agentcore-control"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An ApiKeyCredentialProvider name is not visible through
    GetOauth2CredentialProvider (and vice versa) -- credential provider
    namespaces are isolated by type, not just by name."""
    control = ctx.client("bedrock-agentcore-control")

    api_key_name = ctx.unique_name("sim2real-cp-isolation-apikey-")
    control.create_api_key_credential_provider(
        name=api_key_name,
        apiKey="sk-sim2real-isolation",
        tags={"sim2real-test": "credential-provider-type-isolation-get-rejected"},
    )
    ctx.on_cleanup(
        lambda: _safe_delete(
            lambda: control.delete_api_key_credential_provider(name=api_key_name)
        )
    )

    oauth2_name = ctx.unique_name("sim2real-cp-isolation-oauth2-")
    control.create_oauth2_credential_provider(
        name=oauth2_name,
        credentialProviderVendor="CustomOauth2",
        oauth2ProviderConfigInput={
            "customOauth2ProviderConfig": {
                "oauthDiscovery": {
                    "discoveryUrl": "https://example.com/.well-known/openid-configuration"
                },
                "clientId": "sim2real-isolation-client-id",
                "clientSecret": "sim2real-isolation-client-secret",
            }
        },
        tags={"sim2real-test": "credential-provider-type-isolation-get-rejected"},
    )
    ctx.on_cleanup(
        lambda: _safe_delete(
            lambda: control.delete_oauth2_credential_provider(name=oauth2_name)
        )
    )

    # cross-type Get calls must not find the other type's provider.
    code_a, message_a = _error_detail(
        lambda: control.get_oauth2_credential_provider(name=api_key_name)
    )
    assert code_a == "ResourceNotFoundException", (
        f"GetOauth2CredentialProvider on an ApiKey-typed name {api_key_name!r} "
        f"expected ResourceNotFoundException, got {code_a!r}"
    )
    expected_message_a = "CredentialProvider not found"
    assert message_a == expected_message_a, f"expected message {expected_message_a!r}, got {message_a!r}"

    code_b, message_b = _error_detail(
        lambda: control.get_api_key_credential_provider(name=oauth2_name)
    )
    assert code_b == "ResourceNotFoundException", (
        f"GetApiKeyCredentialProvider on an Oauth2-typed name {oauth2_name!r} "
        f"expected ResourceNotFoundException, got {code_b!r}"
    )
    expected_message_b = f"ApiKeyCredentialProvider not found for {oauth2_name}"
    assert message_b == expected_message_b, f"expected message {expected_message_b!r}, got {message_b!r}"

    # positive control: each provider is found through its own correct type.
    own_api_key = control.get_api_key_credential_provider(name=api_key_name)
    assert own_api_key["name"] == api_key_name, (
        f"expected GetApiKeyCredentialProvider to return name={api_key_name!r}, "
        f"got {own_api_key['name']!r}"
    )

    own_oauth2 = control.get_oauth2_credential_provider(name=oauth2_name)
    assert own_oauth2["name"] == oauth2_name, (
        f"expected GetOauth2CredentialProvider to return name={oauth2_name!r}, "
        f"got {own_oauth2['name']!r}"
    )


def _error_detail(fn):
    """Return (code, message) of the ClientError fn raises; a success raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _safe_delete(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
