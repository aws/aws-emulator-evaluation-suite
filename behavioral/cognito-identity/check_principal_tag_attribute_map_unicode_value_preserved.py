"""principal-tag-attribute-map-unicode-value-preserved."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "principal-tag-attribute-map-unicode-value-preserved"
GROUP = "representation"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Unicode claim keys/values set via SetPrincipalTagAttributeMap are returned byte-identical
    by GetPrincipalTagAttributeMap."""
    ci = ctx.client("cognito-identity")
    idp = ctx.client("cognito-idp")

    # NB: SetPrincipalTagAttributeMap's IdentityProviderName must be a provider actually
    # configured on the identity pool (empirically, an arbitrary DeveloperProviderName string is
    # NOT accepted here -- developer identities pass PrincipalTags directly on
    # GetOpenIdTokenForDeveloperIdentity instead). Use a real Cognito User Pool provider.
    up = idp.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-up-"))
    up_id = up["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=up_id))
    client = idp.create_user_pool_client(
        UserPoolId=up_id, ClientName=ctx.unique_name("sim2real-behav-upc-"), GenerateSecret=False
    )
    client_id = client["UserPoolClient"]["ClientId"]
    provider_name = f"cognito-idp.{ctx.region}.amazonaws.com/{up_id}"

    pool = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-behav-pool-"),
        AllowUnauthenticatedIdentities=False,
        CognitoIdentityProviders=[
            {"ProviderName": provider_name, "ClientId": client_id, "ServerSideTokenCheck": False}
        ],
    )
    pool_id = pool["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))

    tag_key = "\u90e8\u9580Tag"  # "department" in Chinese + "Tag"
    tag_value = "\u00e9quipe-eng"  # French accented characters (no emoji: PrincipalTags values
    # are IAM session-tag values and are constrained similarly to IdentityPoolName -- keep to
    # Unicode letters, no Symbol-category codepoints).

    ci.set_principal_tag_attribute_map(
        IdentityPoolId=pool_id,
        IdentityProviderName=provider_name,
        UseDefaults=False,
        PrincipalTags={tag_key: tag_value},
    )

    got = ci.get_principal_tag_attribute_map(
        IdentityPoolId=pool_id,
        IdentityProviderName=provider_name,
    )
    assert got["PrincipalTags"] == {tag_key: tag_value}, (
        "GetPrincipalTagAttributeMap did not preserve the unicode key/value byte-identically: "
        f"expected {{{tag_key!r}: {tag_value!r}}}, got {got['PrincipalTags']!r}"
    )
    assert got["UseDefaults"] is False, f"expected UseDefaults=False, got {got['UseDefaults']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
