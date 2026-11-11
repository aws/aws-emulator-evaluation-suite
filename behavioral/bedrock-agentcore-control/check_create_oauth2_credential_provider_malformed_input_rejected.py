"""create-oauth2-credential-provider-malformed-input-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-oauth2-credential-provider-malformed-input-rejected"
GROUP = "error-semantics"
SERVICES = ["bedrock-agentcore-control"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateOauth2CredentialProvider with a discoveryUrl lacking the /.well-known/ suffix is refused with
    ValidationException and the exact pattern message and creates nothing; a well-formed discoveryUrl is created and
    read back unchanged."""
    client = ctx.client("bedrock-agentcore-control")

    bad_name = _pattern_safe_name(ctx, "sim2realoauthbad")
    code, message = _error_detail(
        lambda: client.create_oauth2_credential_provider(
            name=bad_name,
            credentialProviderVendor="CustomOauth2",
            oauth2ProviderConfigInput={
                "customOauth2ProviderConfig": {
                    "oauthDiscovery": {"discoveryUrl": "https://example.com/not-a-discovery-endpoint"},
                    "clientId": "sim2real-client-id",
                    "clientSecret": "sim2real-client-secret",
                }
            },
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected = (
        "1 validation error detected: Value at "
        "'oauth2ProviderConfigInput.customOauth2ProviderConfig.oauthDiscovery.discoveryUrl' "
        "failed to satisfy constraint: Member must satisfy regular expression pattern: "
        r"[^\s?#]+/\.well-known/(openid-configuration|oauth-authorization-server)(/[^\s?#]+)?"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the malformed provider was never created.
    assert not _provider_exists(client, bad_name), f"provider {bad_name} exists despite rejected create"

    # Positive control: a well-formed discoveryUrl (matching the documented pattern)
    # succeeds.
    good_name = _pattern_safe_name(ctx, "sim2realoauthgood")
    good_discovery_url = "https://example.com/.well-known/openid-configuration"
    created = client.create_oauth2_credential_provider(
        name=good_name,
        credentialProviderVendor="CustomOauth2",
        oauth2ProviderConfigInput={
            "customOauth2ProviderConfig": {
                "oauthDiscovery": {"discoveryUrl": good_discovery_url},
                "clientId": "sim2real-client-id",
                "clientSecret": "sim2real-client-secret",
            }
        },
        tags={"sim2real-check": CHECK},
    )
    ctx.on_cleanup(lambda: _best_effort_delete(client, good_name))
    assert created["name"] == good_name, f"expected create to echo name {good_name}, got {created.get('name')!r}"

    # Terminal read: independent of the create call, at a GetOauth2CredentialProvider
    # read, proving the well-formed discoveryUrl was actually stored and is served back.
    fetched = client.get_oauth2_credential_provider(name=good_name)
    stored_url = fetched["oauth2ProviderConfigOutput"]["customOauth2ProviderConfig"]["oauthDiscovery"]["discoveryUrl"]
    assert stored_url == good_discovery_url, (
        f"expected the well-formed discoveryUrl {good_discovery_url!r} to be stored, got {stored_url!r}"
    )


def _error_detail(fn):
    """Return (code, message) of the ClientError fn raises; a success raises AssertionError."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _pattern_safe_name(ctx, prefix: str) -> str:
    raw = ctx.unique_name(prefix)
    safe = "".join(c for c in raw if c.isalnum() or c in "-_")
    return safe[:128]


def _provider_exists(client, name: str) -> bool:
    next_token = None
    while True:
        kwargs = {"nextToken": next_token} if next_token else {}
        page = client.list_oauth2_credential_providers(**kwargs)
        for item in page.get("credentialProviders", []):
            if item.get("name") == name:
                return True
        next_token = page.get("nextToken")
        if not next_token:
            return False


def _best_effort_delete(client, name: str) -> None:
    try:
        client.delete_oauth2_credential_provider(name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
