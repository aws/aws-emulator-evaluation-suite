"""create-identity-pool-duplicate-provider-name-accepted-without-dedup."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-identity-pool-duplicate-provider-name-accepted-without-dedup"
GROUP = "representation"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateIdentityPool stores two CognitoIdentityProviders entries with the same ProviderName
    (two app clients on one user pool) verbatim, neither rejecting nor deduplicating them;
    a single-provider baseline is stored as given."""
    idp = ctx.client("cognito-idp")
    identity = ctx.client("cognito-identity")

    pool_id = idp.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-up-"))["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    provider_name = f"cognito-idp.{ctx.region}.amazonaws.com/{pool_id}"

    def _create_client(prefix: str) -> str:
        resp = idp.create_user_pool_client(
            UserPoolId=pool_id,
            ClientName=ctx.unique_name(prefix),
            ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
            GenerateSecret=False,
        )
        return resp["UserPoolClient"]["ClientId"]

    client_1 = _create_client("sim2real-behav-upc1-")
    client_2 = _create_client("sim2real-behav-upc2-")

    # baseline: a single provider entry is stored as given
    baseline_name = ctx.unique_name("sim2real-pool-baseline-")
    baseline_pool_id = identity.create_identity_pool(
        IdentityPoolName=baseline_name,
        AllowUnauthenticatedIdentities=True,
        CognitoIdentityProviders=[{"ProviderName": provider_name, "ClientId": client_1}],
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: identity.delete_identity_pool(IdentityPoolId=baseline_pool_id))
    baseline_described = identity.describe_identity_pool(IdentityPoolId=baseline_pool_id)
    baseline_stored = [
        (p["ProviderName"], p["ClientId"])
        for p in baseline_described.get("CognitoIdentityProviders", [])
    ]
    assert baseline_stored == [(provider_name, client_1)], (
        f"expected exactly one stored provider, got {baseline_described.get('CognitoIdentityProviders')!r}"
    )

    # the SAME ProviderName listed twice, once per app client on the pool -- accepted, not
    # rejected and not deduplicated
    dup_name = ctx.unique_name("sim2real-pool-dup-")
    dup_pool_id = identity.create_identity_pool(
        IdentityPoolName=dup_name,
        AllowUnauthenticatedIdentities=True,
        CognitoIdentityProviders=[
            {"ProviderName": provider_name, "ClientId": client_1},
            {"ProviderName": provider_name, "ClientId": client_2},
        ],
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: identity.delete_identity_pool(IdentityPoolId=dup_pool_id))

    # independent read, at the destination
    dup_described = identity.describe_identity_pool(IdentityPoolId=dup_pool_id)
    dup_stored = [
        (p["ProviderName"], p["ClientId"])
        for p in dup_described.get("CognitoIdentityProviders", [])
    ]
    assert sorted(dup_stored) == sorted([(provider_name, client_1), (provider_name, client_2)]), (
        f"expected both same-ProviderName entries to survive verbatim, got {dup_stored!r}"
    )

    names = [
        p["IdentityPoolName"]
        for page in identity.get_paginator("list_identity_pools").paginate(MaxResults=60)
        for p in page.get("IdentityPools", [])
    ]
    assert dup_name in names, "the accepted duplicate-provider-name pool must be visible in list_identity_pools"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
