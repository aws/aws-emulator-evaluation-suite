"""principal-tag-attribute-map-roundtrip."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "principal-tag-attribute-map-roundtrip"
GROUP = "data-plane"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SetPrincipalTagAttributeMap/GetPrincipalTagAttributeMap round-trip against a real user pool provider."""
    idp = ctx.client("cognito-idp")
    ci = ctx.client("cognito-identity")

    user_pool_name = ctx.unique_name("sim2real-userpool-")
    user_pool_id = idp.create_user_pool(
        PoolName=user_pool_name, UserPoolTags={"sim2real": CHECK}
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=user_pool_id))

    client_name = ctx.unique_name("sim2real-client-")
    client_id = idp.create_user_pool_client(
        UserPoolId=user_pool_id, ClientName=client_name
    )["UserPoolClient"]["ClientId"]

    provider_name = f"cognito-idp.{ctx.region}.amazonaws.com/{user_pool_id}"

    pool_id = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real_pool_").replace("-", "_"),
        AllowUnauthenticatedIdentities=True,
        CognitoIdentityProviders=[
            {"ProviderName": provider_name, "ClientId": client_id, "ServerSideTokenCheck": False}
        ],
        IdentityPoolTags={"sim2real": CHECK},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))

    ci.set_principal_tag_attribute_map(
        IdentityPoolId=pool_id, IdentityProviderName=provider_name, UseDefaults=True
    )
    got_defaults = _get_with_retry(ci, pool_id, provider_name)
    assert got_defaults["UseDefaults"] is True, (
        f"expected UseDefaults=True to round-trip, got {got_defaults['UseDefaults']!r}"
    )

    custom_map = {"sim2real:sub": "sub", "sim2real:email": "email"}
    ci.set_principal_tag_attribute_map(
        IdentityPoolId=pool_id,
        IdentityProviderName=provider_name,
        UseDefaults=False,
        PrincipalTags=custom_map,
    )
    got_custom = _get_with_retry(ci, pool_id, provider_name)
    assert got_custom["UseDefaults"] is False, (
        f"expected UseDefaults=False after setting a custom map, got {got_custom['UseDefaults']!r}"
    )
    assert got_custom.get("PrincipalTags") == custom_map, (
        f"expected PrincipalTags {custom_map}, got {got_custom.get('PrincipalTags')}"
    )


def _get_with_retry(ci, pool_id: str, provider_name: str, attempts: int = 5) -> dict:
    last_exc = None
    for _ in range(attempts):
        try:
            return ci.get_principal_tag_attribute_map(
                IdentityPoolId=pool_id, IdentityProviderName=provider_name
            )
        except Exception as exc:  # eventual consistency after Set
            last_exc = exc
            time.sleep(2)
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
