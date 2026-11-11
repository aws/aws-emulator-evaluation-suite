"""concurrent-set-principal-tag-attribute-map-consistent."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-set-principal-tag-attribute-map-consistent"
GROUP = "concurrency"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Racing SetPrincipalTagAttributeMap calls converge to one complete map, never an interleaved mix."""
    pool_id, provider_name = _create_pool_with_provider(ctx)
    ci = ctx.client("cognito-identity")

    candidate_maps = [
        {"department": "custom:department", "region": "custom:region"},
        {"team": "custom:team", "cost-center": "custom:cost_center"},
        {"role-name": "custom:role_name", "org": "custom:org"},
    ]

    def _set(tags_map: dict) -> None:
        ci.set_principal_tag_attribute_map(
            IdentityPoolId=pool_id,
            IdentityProviderName=provider_name,
            UseDefaults=False,
            PrincipalTags=tags_map,
        )

    with ThreadPoolExecutor(max_workers=len(candidate_maps)) as pool:
        futures = [pool.submit(_set, m) for m in candidate_maps]
        for f in futures:
            f.result(timeout=30)

    final = ci.get_principal_tag_attribute_map(
        IdentityPoolId=pool_id, IdentityProviderName=provider_name
    )["PrincipalTags"]

    assert final in candidate_maps, (
        f"final PrincipalTags {final} is not exactly one of the racing complete maps "
        f"{candidate_maps} (interleaved/partial state observed)"
    )

    # Stable on repeated reads.
    for _ in range(3):
        again = ci.get_principal_tag_attribute_map(
            IdentityPoolId=pool_id, IdentityProviderName=provider_name
        )["PrincipalTags"]
        assert again == final, "principal tag attribute map is not stable after the race settled"


def _create_pool_with_provider(ctx):
    idp = ctx.client("cognito-idp")
    user_pool = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-up-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
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
        IdentityPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))
    return pool_id, provider_name


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
