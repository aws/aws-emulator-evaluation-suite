"""principal-tag-attribute-map-special-char-values-preserved."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "principal-tag-attribute-map-special-char-values-preserved"
GROUP = "representation"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PrincipalTagAttributeMap values containing special/unicode characters persist
    byte-identical through Set/GetPrincipalTagAttributeMap."""
    ci = ctx.client("cognito-identity")
    pool_id, provider_name = _create_pool_with_provider(ctx)

    principal_tags = {
        "department": "Engineering & R\u0026D \u2013 \u00c9quipe",
        "clearance": "\u674e\u4e94:level<=3&!admin",
        "note": '  quoted "value" with\ttab and \u00e9moji-less unicode \u00df  ',
    }

    ci.set_principal_tag_attribute_map(
        IdentityPoolId=pool_id,
        IdentityProviderName=provider_name,
        UseDefaults=False,
        PrincipalTags=principal_tags,
    )

    got = ci.get_principal_tag_attribute_map(
        IdentityPoolId=pool_id, IdentityProviderName=provider_name
    )
    assert got["UseDefaults"] is False
    assert got["PrincipalTags"] == principal_tags, (
        f"PrincipalTags mismatch: {got['PrincipalTags']!r} != {principal_tags!r}"
    )


def _create_pool_with_provider(ctx) -> tuple[str, str]:
    ci = ctx.client("cognito-identity")
    provider_name = f"cognito-idp.{ctx.region}.amazonaws.com/{ctx.region}_sim2realfake01"
    pool_id = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-"),
        AllowUnauthenticatedIdentities=True,
        CognitoIdentityProviders=[
            {
                "ProviderName": provider_name,
                "ClientId": "sim2realfakeclientid123",
            }
        ],
        IdentityPoolTags={"sim2real-check": "principal-tag-attribute-map-special-char-values-preserved"},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))
    return pool_id, provider_name


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
