"""principal-tag-attribute-map-set-get-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "principal-tag-attribute-map-set-get-lifecycle"
GROUP = "state-machine"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SetPrincipalTagAttributeMap persists a mapping GetPrincipalTagAttributeMap returns verbatim."""
    ci = ctx.client("cognito-identity")
    provider_name = "graph.facebook.com"
    # Real AWS rejects SetPrincipalTagAttributeMap with InvalidParameterException ("Provider
    # graph.facebook.com not configured for Identity Pool") unless the provider is registered on
    # the pool via SupportedLoginProviders.
    pool_id = _create_pool(
        ctx, SupportedLoginProviders={provider_name: ctx.unique_name("app-")}
    )
    principal_tags = {"department": "sub", "email": "email"}

    ci.set_principal_tag_attribute_map(
        IdentityPoolId=pool_id,
        IdentityProviderName=provider_name,
        UseDefaults=False,
        PrincipalTags=principal_tags,
    )

    resp = ci.get_principal_tag_attribute_map(
        IdentityPoolId=pool_id, IdentityProviderName=provider_name
    )
    assert resp["IdentityPoolId"] == pool_id
    assert resp["IdentityProviderName"] == provider_name
    assert resp["UseDefaults"] is False, resp
    assert resp["PrincipalTags"] == principal_tags, resp["PrincipalTags"]


def _create_pool(ctx, **extra) -> str:
    ci = ctx.client("cognito-identity")
    name = extra.pop("IdentityPoolName", None) or ctx.unique_name("sim2real-behav-")
    allow_unauth = extra.pop("AllowUnauthenticatedIdentities", True)
    resp = ci.create_identity_pool(
        IdentityPoolName=name, AllowUnauthenticatedIdentities=allow_unauth, **extra
    )
    pool_id = resp["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))
    return pool_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
