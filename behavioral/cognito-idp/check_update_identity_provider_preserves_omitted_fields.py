"""update-identity-provider-preserves-omitted-fields."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-identity-provider-preserves-omitted-fields"
GROUP = "state-machine"
SERVICES = ["cognito-idp"]

_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}

_DETAILS_V1 = {
    "client_id": "sim2real-behav-client-id",
    "client_secret": "sim2real-behav-client-secret",
    "attributes_request_method": "GET",
    "oidc_issuer": "https://sim2real-behav.example.com/oidc",
    "authorize_scopes": "openid",
    "authorize_url": "https://sim2real-behav.example.com/oidc/authorize",
    "token_url": "https://sim2real-behav.example.com/oidc/token",
    "attributes_url": "https://sim2real-behav.example.com/oidc/userinfo",
    "jwks_uri": "https://sim2real-behav.example.com/oidc/jwks",
}

_DETAILS_V2 = dict(_DETAILS_V1, authorize_url="https://sim2real-behav.example.com/oidc/authorize-v2")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateIdentityProvider that supplies only ProviderDetails leaves AttributeMapping
    and IdpIdentifiers exactly as created, while still applying the ProviderDetails change."""
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), UserPoolTags=_TAGS
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    provider_name = ctx.unique_name("sim2realbehavoidc").replace("-", "")[:32]
    idp_identifier = ctx.unique_name("sim2realbehavalias").replace("-", "")[:32]
    attribute_mapping = {"email": "email", "username": "sub"}

    idp.create_identity_provider(
        UserPoolId=pool_id,
        ProviderName=provider_name,
        ProviderType="OIDC",
        ProviderDetails=_DETAILS_V1,
        AttributeMapping=attribute_mapping,
        IdpIdentifiers=[idp_identifier],
    )
    ctx.on_cleanup(
        lambda: idp.delete_identity_provider(UserPoolId=pool_id, ProviderName=provider_name)
    )

    # The update omits AttributeMapping and IdpIdentifiers entirely -- it must not be read
    # as "clear them", and it must still apply the ProviderDetails change it did send.
    idp.update_identity_provider(
        UserPoolId=pool_id,
        ProviderName=provider_name,
        ProviderDetails=_DETAILS_V2,
    )

    provider = idp.describe_identity_provider(UserPoolId=pool_id, ProviderName=provider_name)[
        "IdentityProvider"
    ]
    assert provider["AttributeMapping"] == attribute_mapping, (
        f"expected AttributeMapping to survive an update that omitted it, "
        f"got {provider['AttributeMapping']!r}"
    )
    assert provider["IdpIdentifiers"] == [idp_identifier], (
        f"expected IdpIdentifiers to survive an update that omitted it, "
        f"got {provider['IdpIdentifiers']!r}"
    )
    assert provider["ProviderDetails"]["authorize_url"] == _DETAILS_V2["authorize_url"], (
        f"expected the ProviderDetails member the update DID send to apply, "
        f"got authorize_url={provider['ProviderDetails'].get('authorize_url')!r}"
    )

    by_ident = idp.get_identity_provider_by_identifier(
        UserPoolId=pool_id, IdpIdentifier=idp_identifier
    )["IdentityProvider"]
    assert by_ident["ProviderName"] == provider_name, (
        f"expected the untouched identifier to still resolve {provider_name!r}, "
        f"got {by_ident['ProviderName']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
