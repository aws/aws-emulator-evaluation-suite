"""resource-server-scope-update-does-not-cascade-to-client."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "resource-server-scope-update-does-not-cascade-to-client"
GROUP = 'scope-consistency'
SERVICES = ['cognito-idp']


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateResourceServer dropping a scope shows in DescribeResourceServer, but an existing
    client's AllowedOAuthScopes still lists the dropped scope: Cognito does not cascade
    resource-server scope changes to clients."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"})["UserPool"]["Id"]
    ctx.on_cleanup(lambda _id=pool_id: c.delete_user_pool(UserPoolId=_id))
    identifier = ctx.unique_name("sim2real-behav-cip-scoperes-")
    c.create_resource_server(
        UserPoolId=pool_id,
        Identifier=identifier,
        Name="scoped-api",
        Scopes=[
            {"ScopeName": "read", "ScopeDescription": "read access"},
            {"ScopeName": "write", "ScopeDescription": "write access"},
        ],
    )
    ctx.on_cleanup(lambda _p=pool_id, _i=identifier: c.delete_resource_server(UserPoolId=_p, Identifier=_i))

    read_scope = f"{identifier}/read"
    client_id = c.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-cip-client-"),
        GenerateSecret=True,
        AllowedOAuthFlows=["client_credentials"],
        AllowedOAuthScopes=[read_scope],
        AllowedOAuthFlowsUserPoolClient=True,
    )["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(lambda _p=pool_id, _c=client_id: c.delete_user_pool_client(UserPoolId=_p, ClientId=_c))
    desc_before = c.describe_user_pool_client(UserPoolId=pool_id, ClientId=client_id)["UserPoolClient"]
    assert desc_before["AllowedOAuthScopes"] == [read_scope], desc_before["AllowedOAuthScopes"]

    c.update_resource_server(
        UserPoolId=pool_id,
        Identifier=identifier,
        Name="scoped-api",
        Scopes=[{"ScopeName": "write", "ScopeDescription": "write access only now"}],
    )
    rs_after = c.describe_resource_server(UserPoolId=pool_id, Identifier=identifier)["ResourceServer"]
    assert [s["ScopeName"] for s in rs_after["Scopes"]] == ["write"], rs_after["Scopes"]

    desc_after = c.describe_user_pool_client(UserPoolId=pool_id, ClientId=client_id)["UserPoolClient"]
    assert desc_after["AllowedOAuthScopes"] == [read_scope], (
        f"expected the client's AllowedOAuthScopes to remain {[read_scope]} even though the "
        f"resource server no longer defines that scope, got {desc_after['AllowedOAuthScopes']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
