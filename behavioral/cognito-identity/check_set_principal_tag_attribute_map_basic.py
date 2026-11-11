"""set-principal-tag-attribute-map-basic."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "set-principal-tag-attribute-map-basic"
GROUP = "server-side"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SetPrincipalTagAttributeMap persists a mapping returned verbatim by Get."""
    ci = ctx.client("cognito-identity")
    # Principal tags require the target IdentityProviderName to be one of the
    # pool's supported login providers (or a Cognito user pool / SAML / OIDC
    # provider) — a DeveloperProviderName is not accepted here ("Provider ...
    # not configured for Identity Pool" on real AWS).
    login_provider = "graph.facebook.com"
    pool_id = _create_pool(ctx, ci, login_provider=login_provider)

    tags_map = {"department": "custom:department", "employeeId": "custom:employee_id"}
    set_resp = ci.set_principal_tag_attribute_map(
        IdentityPoolId=pool_id,
        IdentityProviderName=login_provider,
        UseDefaults=False,
        PrincipalTags=tags_map,
    )
    assert set_resp["PrincipalTags"] == tags_map, (
        f"expected SetPrincipalTagAttributeMap to echo {tags_map}, got {set_resp.get('PrincipalTags')!r}"
    )
    assert set_resp["UseDefaults"] is False, set_resp
    assert set_resp["IdentityPoolId"] == pool_id, set_resp
    assert set_resp["IdentityProviderName"] == login_provider, set_resp

    get_resp = ci.get_principal_tag_attribute_map(
        IdentityPoolId=pool_id, IdentityProviderName=login_provider
    )
    assert get_resp["PrincipalTags"] == tags_map, (
        f"expected GetPrincipalTagAttributeMap to read back {tags_map}, got {get_resp.get('PrincipalTags')!r}"
    )
    assert get_resp["UseDefaults"] is False, get_resp
    assert get_resp["IdentityPoolId"] == pool_id, get_resp
    assert get_resp["IdentityProviderName"] == login_provider, get_resp


def _create_pool(ctx, ci, *, unauth: bool = True, login_provider: str | None = None) -> str:
    kwargs = {
        "IdentityPoolName": ctx.unique_name("sim2real-behav-pool-"),
        "AllowUnauthenticatedIdentities": unauth,
        "IdentityPoolTags": {"sim2real": CHECK},
    }
    if login_provider:
        kwargs["SupportedLoginProviders"] = {login_provider: ctx.unique_name("app-")}
    pool_id = ci.create_identity_pool(**kwargs)["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))
    return pool_id



if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
