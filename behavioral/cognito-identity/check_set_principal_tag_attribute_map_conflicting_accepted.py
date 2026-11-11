"""set-principal-tag-attribute-map-conflicting-accepted."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "set-principal-tag-attribute-map-conflicting-accepted"
GROUP = "overly-permissive"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SetPrincipalTagAttributeMap with UseDefaults=True and a custom PrincipalTags map is accepted,
    but UseDefaults wins: GetPrincipalTagAttributeMap reports none of the conflicting custom pairs."""
    ci = ctx.client("cognito-identity")
    idp = ctx.client("cognito-idp")

    # CreateIdentityPool rejects a CognitoIdentityProviders entry that does not reference an
    # existing user pool, so a real one is needed.
    user_pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-up-"),
        UserPoolTags={"sim2real": CHECK},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=user_pool_id))

    app_client_id = idp.create_user_pool_client(
        UserPoolId=user_pool_id,
        ClientName=ctx.unique_name("sim2real-behav-client-"),
    )["UserPoolClient"]["ClientId"]

    provider_name = f"cognito-idp.{ctx.region}.amazonaws.com/{user_pool_id}"

    pool_id = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-behav-"),
        AllowUnauthenticatedIdentities=True,
        CognitoIdentityProviders=[
            {
                "ProviderName": provider_name,
                "ClientId": app_client_id,
                "ServerSideTokenCheck": False,
            }
        ],
        IdentityPoolTags={"sim2real": CHECK},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))

    conflicting_tags = {"department": "sub"}
    # the contradictory request is accepted; a refusal raises here.
    ci.set_principal_tag_attribute_map(
        IdentityPoolId=pool_id,
        IdentityProviderName=provider_name,
        UseDefaults=True,
        PrincipalTags=conflicting_tags,
    )

    got = ci.get_principal_tag_attribute_map(
        IdentityPoolId=pool_id, IdentityProviderName=provider_name
    )
    assert got["UseDefaults"] is True, f"expected UseDefaults=True to win, got {got!r}"
    # AWS reports the provider's non-empty default mapping here; check each custom pair
    # individually so a custom map merged into the defaults still fails.
    principal_tags = got.get("PrincipalTags") or {}
    for key, value in conflicting_tags.items():
        assert principal_tags.get(key) != value, (
            f"conflicting mapping {key!r}->{value!r} must not be applied when UseDefaults=True, "
            f"got {got!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
