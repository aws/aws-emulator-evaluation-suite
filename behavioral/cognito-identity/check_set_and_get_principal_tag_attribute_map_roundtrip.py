"""set-and-get-principal-tag-attribute-map-roundtrip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "set-and-get-principal-tag-attribute-map-roundtrip"
GROUP = "principal-tags"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SetPrincipalTagAttributeMap persists UseDefaults/PrincipalTags for a registered identity
    provider; GetPrincipalTagAttributeMap reads back exactly what was configured."""
    ci = ctx.client("cognito-identity")
    idp = ctx.client("cognito-idp")

    # Real AWS validates that a CognitoIdentityProviders entry references an actual, existing
    # Cognito User Pool -- a made-up provider name is rejected with InvalidParameterException.
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

    principal_tags = {"department": "sub", "email": "email"}
    set_resp = ci.set_principal_tag_attribute_map(
        IdentityPoolId=pool_id,
        IdentityProviderName=provider_name,
        UseDefaults=False,
        PrincipalTags=principal_tags,
    )
    assert set_resp["UseDefaults"] is False, set_resp
    assert set_resp["PrincipalTags"] == principal_tags, set_resp

    got = ci.get_principal_tag_attribute_map(
        IdentityPoolId=pool_id, IdentityProviderName=provider_name
    )
    assert got["IdentityPoolId"] == pool_id, got
    assert got["IdentityProviderName"] == provider_name, got
    assert got["UseDefaults"] is False, got
    assert got["PrincipalTags"] == principal_tags, got


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
