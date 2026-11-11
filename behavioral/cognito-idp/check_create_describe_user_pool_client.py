"""create-describe-user-pool-client."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "create-describe-user-pool-client"
GROUP = 'user-pool-client-lifecycle'
SERVICES = ['cognito-idp']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateUserPoolClient followed by DescribeUserPoolClient returns matching metadata."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"})["UserPool"]["Id"]
    ctx.on_cleanup(lambda _id=pool_id: c.delete_user_pool(UserPoolId=_id))
    name = ctx.unique_name("sim2real-behav-cip-client-")
    client_id = c.create_user_pool_client(UserPoolId=pool_id, ClientName=name)["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(lambda _p=pool_id, _c=client_id: c.delete_user_pool_client(UserPoolId=_p, ClientId=_c))

    desc = c.describe_user_pool_client(UserPoolId=pool_id, ClientId=client_id)[
        "UserPoolClient"
    ]
    assert desc["ClientId"] == client_id, f"expected ClientId {client_id!r}, got {desc['ClientId']!r}"
    assert desc["ClientName"] == name, f"expected ClientName {name!r}, got {desc['ClientName']!r}"
    assert desc["UserPoolId"] == pool_id, f"expected UserPoolId {pool_id!r}, got {desc['UserPoolId']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
