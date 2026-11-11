"""update-user-pool-client-reflects-changes."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "update-user-pool-client-reflects-changes"
GROUP = 'user-pool-client-lifecycle'
SERVICES = ['cognito-idp']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateUserPoolClient with only RefreshTokenValidity 45 shows 45 in DescribeUserPoolClient, keeps
    the ClientName and clears the omitted ExplicitAuthFlows rather than merging them."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"})["UserPool"]["Id"]
    ctx.on_cleanup(lambda _id=pool_id: c.delete_user_pool(UserPoolId=_id))
    client_name = ctx.unique_name("sim2real-behav-cip-client-")
    auth_flows = ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]
    client_id = c.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=client_name,
        ExplicitAuthFlows=auth_flows,
    )["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(lambda _p=pool_id, _c=client_id: c.delete_user_pool_client(UserPoolId=_p, ClientId=_c))

    c.update_user_pool_client(
        UserPoolId=pool_id,
        ClientId=client_id,
        RefreshTokenValidity=45,
    )
    desc = c.describe_user_pool_client(UserPoolId=pool_id, ClientId=client_id)[
        "UserPoolClient"
    ]
    assert desc["RefreshTokenValidity"] == 45, (
        f"expected RefreshTokenValidity 45, got {desc['RefreshTokenValidity']}"
    )
    assert desc["ClientName"] == client_name, (
        f"an update naming only RefreshTokenValidity must not change ClientName: "
        f"expected {client_name!r}, got {desc['ClientName']!r}"
    )
    assert desc.get("ExplicitAuthFlows", []) == [], (
        "UpdateUserPoolClient replaces the whole writable attribute set, not just the "
        f"named fields: an update naming only RefreshTokenValidity must clear "
        f"ExplicitAuthFlows, got {desc.get('ExplicitAuthFlows', [])}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
