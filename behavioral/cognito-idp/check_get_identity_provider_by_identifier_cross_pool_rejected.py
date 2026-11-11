"""get-identity-provider-by-identifier-cross-pool-rejected."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "get-identity-provider-by-identifier-cross-pool-rejected"
GROUP = "data-plane"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An IdpIdentifier registered on one user pool must not resolve when queried
    against a different, unrelated user pool -- GetIdentityProviderByIdentifier is
    scoped per pool, not global across the account."""
    idp = ctx.client("cognito-idp")

    pool_tags = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
    pool_a = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-pool-a-"), UserPoolTags=pool_tags
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_a))
    pool_b = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-pool-b-"), UserPoolTags=pool_tags
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_b))

    provider_name = f"sim2realidp{uuid.uuid4().hex[:10]}"
    identifier = ctx.unique_name("sim2real-idpid-")
    idp.create_identity_provider(
        UserPoolId=pool_a,
        ProviderName=provider_name,
        ProviderType="OIDC",
        ProviderDetails={
            "client_id": "sample-client-id",
            "client_secret": "sample-client-secret",
            "authorize_scopes": "openid profile email",
            "oidc_issuer": "https://sim2real-behav.example.com/oidc",
            "authorize_url": "https://sim2real-behav.example.com/oidc/authorize",
            "token_url": "https://sim2real-behav.example.com/oidc/token",
            "attributes_url": "https://sim2real-behav.example.com/oidc/userinfo",
            "jwks_uri": "https://sim2real-behav.example.com/oidc/.well-known/jwks.json",
            "attributes_request_method": "GET",
        },
        IdpIdentifiers=[identifier],
    )
    ctx.on_cleanup(lambda: idp.delete_identity_provider(UserPoolId=pool_a, ProviderName=provider_name))

    # Positive control: resolves correctly against the pool it actually belongs to.
    resolved = idp.get_identity_provider_by_identifier(UserPoolId=pool_a, IdpIdentifier=identifier)[
        "IdentityProvider"
    ]
    assert resolved["ProviderName"] == provider_name, (
        f"expected positive control to resolve {provider_name!r}, got {resolved['ProviderName']!r}"
    )

    # Negative: the identical identifier string is unknown in the sibling pool.
    code, message = _error(lambda: idp.get_identity_provider_by_identifier(UserPoolId=pool_b, IdpIdentifier=identifier))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    expected = f"Identity provider {identifier} for tenantId {pool_b} does not exist."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # The effect is absent: pool B's provider list stays empty -- no leakage of pool A's config.
    providers_b = idp.list_identity_providers(UserPoolId=pool_b)["Providers"]
    assert providers_b == [], f"pool B unexpectedly has identity providers: {providers_b}"


def _error(fn):
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
