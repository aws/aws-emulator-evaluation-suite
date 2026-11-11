"""principal-tag-attribute-map-overwrite-semantics."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "principal-tag-attribute-map-overwrite-semantics"
GROUP = "state-machine"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A second SetPrincipalTagAttributeMap call fully replaces the prior mapping (PUT, not merge)."""
    ci = ctx.client("cognito-identity")
    # Principal tags require the target IdentityProviderName to be one of the
    # pool's supported login providers (or a Cognito user pool / SAML / OIDC
    # provider) — a DeveloperProviderName is not accepted here ("Provider ...
    # not configured for Identity Pool" on real AWS).
    login_provider = "graph.facebook.com"
    pool_id = _create_pool(ctx, ci, login_provider=login_provider)

    first_map = {"department": "custom:department", "employeeId": "custom:employee_id"}
    ci.set_principal_tag_attribute_map(
        IdentityPoolId=pool_id,
        IdentityProviderName=login_provider,
        UseDefaults=False,
        PrincipalTags=first_map,
    )
    confirm = ci.get_principal_tag_attribute_map(
        IdentityPoolId=pool_id, IdentityProviderName=login_provider
    )
    assert confirm["PrincipalTags"] == first_map, (
        f"expected first SetPrincipalTagAttributeMap to persist {first_map}, got {confirm.get('PrincipalTags')!r}"
    )

    second_map = {"role": "custom:role"}
    ci.set_principal_tag_attribute_map(
        IdentityPoolId=pool_id,
        IdentityProviderName=login_provider,
        UseDefaults=False,
        PrincipalTags=second_map,
    )
    final = ci.get_principal_tag_attribute_map(
        IdentityPoolId=pool_id, IdentityProviderName=login_provider
    )
    assert final["PrincipalTags"] == second_map, (
        f"expected second Set to fully replace the mapping with {second_map}, got {final.get('PrincipalTags')!r}"
    )
    assert "department" not in final["PrincipalTags"], (
        f"expected first map's 'department' key gone after overwrite, still present in {final['PrincipalTags']!r}"
    )
    assert "employeeId" not in final["PrincipalTags"], (
        f"expected first map's 'employeeId' key gone after overwrite, still present in {final['PrincipalTags']!r}"
    )


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
