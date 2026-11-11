"""get-principal-tag-attribute-map-default-empty."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-principal-tag-attribute-map-default-empty"
GROUP = "error-semantics"
SERVICES = ["cognito-identity"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetPrincipalTagAttributeMap for a provider with no mapping answers ResourceNotFoundException
    with the exact message; after SetPrincipalTagAttributeMap the same call returns the configured
    map."""
    pool_id, provider_name = _create_pool_with_provider(ctx)
    ci = ctx.client("cognito-identity")

    # SetPrincipalTagAttributeMap was never called for this provider on this pool.
    code, message = _error(
        lambda: ci.get_principal_tag_attribute_map(
            IdentityPoolId=pool_id, IdentityProviderName=provider_name
        )
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException before any Set call, got {code!r}"
    )
    expected = f"No Principal Tags configured for Provider {provider_name}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Positive control: the identical Get call succeeds once a mapping is configured, so the
    # rejection above is specific to the never-configured provider.
    custom_map = {"tenant": "custom:tenant"}
    set_resp = ci.set_principal_tag_attribute_map(
        IdentityPoolId=pool_id,
        IdentityProviderName=provider_name,
        UseDefaults=False,
        PrincipalTags=custom_map,
    )
    assert set_resp.get("PrincipalTags") == custom_map, (
        f"expected SetPrincipalTagAttributeMap to echo {custom_map!r}, "
        f"got {set_resp.get('PrincipalTags')!r}"
    )

    got = ci.get_principal_tag_attribute_map(
        IdentityPoolId=pool_id, IdentityProviderName=provider_name
    )
    assert got.get("PrincipalTags") == custom_map, (
        f"expected GetPrincipalTagAttributeMap to now succeed and reflect the mapping "
        f"just configured by SetPrincipalTagAttributeMap, got {got!r}"
    )


def _error(fn):
    """Call fn(); return its ClientError (Code, Message). An unexpected success raises, so a
    target that synthesizes a default map fails loudly."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_pool_with_provider(ctx):
    idp = ctx.client("cognito-idp")
    user_pool = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-up-"),
        UserPoolTags={"sim2real": "get-principal-tag-attribute-map-default-empty"},
    )["UserPool"]
    user_pool_id = user_pool["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=user_pool_id))

    client = idp.create_user_pool_client(
        UserPoolId=user_pool_id,
        ClientName=ctx.unique_name("sim2real-behav-client-"),
        GenerateSecret=False,
    )["UserPoolClient"]
    provider_name = f"cognito-idp.{ctx.region}.amazonaws.com/{user_pool_id}"

    ci = ctx.client("cognito-identity")
    pool_id = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-behav-pool-"),
        AllowUnauthenticatedIdentities=True,
        CognitoIdentityProviders=[{"ProviderName": provider_name, "ClientId": client["ClientId"]}],
        IdentityPoolTags={"sim2real": "get-principal-tag-attribute-map-default-empty"},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))
    return pool_id, provider_name


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
