"""get-identity-provider-by-identifier-matches-created-config."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "get-identity-provider-by-identifier-matches-created-config"
GROUP = "data-plane"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateIdentityProvider with a set of IdpIdentifiers registers a provider that
    GetIdentityProviderByIdentifier later resolves back to the exact ProviderName,
    ProviderType, and ProviderDetails that were configured at creation time."""
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    # OIDC (unlike the social IdP types) allows an arbitrary custom ProviderName --
    # social types such as Facebook require ProviderName to equal the type name.
    provider_name = f"sim2realidp{uuid.uuid4().hex[:10]}"
    identifier = ctx.unique_name("sim2real-idpid-")
    details = {
        "client_id": "sample-client-id-12345",
        "client_secret": "sample-client-secret-67890",
        "authorize_scopes": "openid profile email",
        "oidc_issuer": "https://sim2real-behav.example.com/oidc",
        "authorize_url": "https://sim2real-behav.example.com/oidc/authorize",
        "token_url": "https://sim2real-behav.example.com/oidc/token",
        "attributes_url": "https://sim2real-behav.example.com/oidc/userinfo",
        "jwks_uri": "https://sim2real-behav.example.com/oidc/.well-known/jwks.json",
        "attributes_request_method": "GET",
    }
    idp.create_identity_provider(
        UserPoolId=pool_id,
        ProviderName=provider_name,
        ProviderType="OIDC",
        ProviderDetails=details,
        IdpIdentifiers=[identifier],
    )
    ctx.on_cleanup(lambda: idp.delete_identity_provider(UserPoolId=pool_id, ProviderName=provider_name))

    resolved = idp.get_identity_provider_by_identifier(UserPoolId=pool_id, IdpIdentifier=identifier)[
        "IdentityProvider"
    ]
    assert resolved["ProviderName"] == provider_name, f"expected {provider_name}, got {resolved['ProviderName']}"
    assert resolved["ProviderType"] == "OIDC", f"expected OIDC, got {resolved['ProviderType']}"
    resolved_details = resolved["ProviderDetails"]
    assert resolved_details["client_id"] == details["client_id"], (
        f"client_id: expected {details['client_id']!r}, got {resolved_details['client_id']!r}"
    )
    assert resolved_details["client_secret"] == details["client_secret"], (
        f"client_secret: expected {details['client_secret']!r}, got {resolved_details['client_secret']!r}"
    )
    assert resolved_details["authorize_scopes"] == details["authorize_scopes"], (
        f"authorize_scopes: expected {details['authorize_scopes']!r}, got {resolved_details['authorize_scopes']!r}"
    )
    assert resolved_details["oidc_issuer"] == details["oidc_issuer"], (
        f"oidc_issuer: expected {details['oidc_issuer']!r}, got {resolved_details['oidc_issuer']!r}"
    )
    assert resolved_details["authorize_url"] == details["authorize_url"], (
        f"authorize_url: expected {details['authorize_url']!r}, got {resolved_details['authorize_url']!r}"
    )
    assert resolved_details["token_url"] == details["token_url"], (
        f"token_url: expected {details['token_url']!r}, got {resolved_details['token_url']!r}"
    )
    assert resolved_details["attributes_url"] == details["attributes_url"], (
        f"attributes_url: expected {details['attributes_url']!r}, got {resolved_details['attributes_url']!r}"
    )
    assert resolved_details["jwks_uri"] == details["jwks_uri"], (
        f"jwks_uri: expected {details['jwks_uri']!r}, got {resolved_details['jwks_uri']!r}"
    )
    assert resolved_details["attributes_request_method"] == details["attributes_request_method"], (
        "attributes_request_method: expected "
        f"{details['attributes_request_method']!r}, got {resolved_details['attributes_request_method']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
