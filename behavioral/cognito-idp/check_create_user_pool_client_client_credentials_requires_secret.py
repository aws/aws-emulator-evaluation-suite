"""create-user-pool-client-client-credentials-requires-secret."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-user-pool-client-client-credentials-requires-secret"
GROUP = 'user-pool-client-lifecycle'
SERVICES = ['cognito-idp']


def _error(fn):
    """Call fn(); return the ClientError (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _create_user_pool(idp, ctx, **kwargs):
    """Create a user pool with cleanup; deleting it cascades to its app clients."""
    name = ctx.unique_name("sim2real-behav-cip-pool-")
    pool = idp.create_user_pool(
        PoolName=name,
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
        **kwargs,
    )["UserPool"]
    ctx.on_cleanup(lambda _id=pool["Id"]: idp.delete_user_pool(UserPoolId=_id))
    return pool


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateUserPoolClient with client_credentials and no secret fails with
    InvalidOAuthFlowException and is not persisted, while a secreted client with the same
    flow and scope is created."""
    idp = ctx.client("cognito-idp")
    pool = _create_user_pool(idp, ctx)

    # client_credentials only accepts custom resource-server scopes, so create one.
    resource_server_id = ctx.unique_name("sim2real-behav-cip-rs-")
    idp.create_resource_server(
        UserPoolId=pool["Id"],
        Identifier=resource_server_id,
        Name="sim2real behavioral resource server",
        Scopes=[{"ScopeName": "read", "ScopeDescription": "read access"}],
    )
    valid_scope = [f"{resource_server_id}/read"]

    control_name = ctx.unique_name("sim2real-behav-cip-client-ctrl-")
    control = idp.create_user_pool_client(
        UserPoolId=pool["Id"],
        ClientName=control_name,
        GenerateSecret=True,
        AllowedOAuthFlows=["client_credentials"],
        AllowedOAuthScopes=valid_scope,
        AllowedOAuthFlowsUserPoolClient=True,
    )["UserPoolClient"]
    assert control["ClientSecret"], "positive control: confidential client must have a secret"

    rejected_name = ctx.unique_name("sim2real-behav-cip-client-")

    def attempt():
        return idp.create_user_pool_client(
            UserPoolId=pool["Id"],
            ClientName=rejected_name,
            GenerateSecret=False,
            AllowedOAuthFlows=["client_credentials"],
            AllowedOAuthScopes=valid_scope,
            AllowedOAuthFlowsUserPoolClient=True,
        )

    code, message = _error(attempt)
    assert code == "InvalidOAuthFlowException", (
        f"expected InvalidOAuthFlowException for client_credentials without a secret, got {code}"
    )
    expected_message = "client_credentials flow can not be selected if client does not have a client secret."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    names = {
        cl["ClientName"]
        for cl in idp.list_user_pool_clients(UserPoolId=pool["Id"], MaxResults=60)[
            "UserPoolClients"
        ]
    }
    assert rejected_name not in names, (
        "a client that failed InvalidOAuthFlowException validation must not persist"
    )
    assert control_name in names, "the positive-control confidential client must persist"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
