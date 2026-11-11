"""create-user-pool-client-invalid-scope-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-user-pool-client-invalid-scope-rejected"
GROUP = 'overly-permissive'
SERVICES = ['cognito-idp']

_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


def _error(fn):
    """Call fn(); return the botocore Error code and message. An unexpected SUCCESS raises, because
    an emulator ACCEPTING a scope real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(
        f"real AWS rejects this scope, but the call SUCCEEDED and returned {result!r}"
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateUserPoolClient with an OAuth scope no resource server defines is refused with
    ScopeDoesNotExistException and the exact message and creates no client, while a defined scope is
    accepted and stored."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), UserPoolTags=_TAGS
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: c.delete_user_pool(UserPoolId=pool_id))

    resource_server_id = ctx.unique_name("sim2real-behav-cip-res-")
    c.create_resource_server(
        UserPoolId=pool_id,
        Identifier=resource_server_id,
        Name=resource_server_id,
        Scopes=[{"ScopeName": "read", "ScopeDescription": "read access"}],
    )
    valid_scope = f"{resource_server_id}/read"
    bogus_scope = f"{resource_server_id}/nonexistent.scope"

    # Positive control: the same call shape, a scope that IS defined on a resource server.
    good_client_name = ctx.unique_name("sim2real-behav-cip-client-ok-")
    good = c.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=good_client_name,
        GenerateSecret=True,
        AllowedOAuthFlows=["client_credentials"],
        AllowedOAuthScopes=[valid_scope],
        AllowedOAuthFlowsUserPoolClient=True,
    )["UserPoolClient"]
    ctx.on_cleanup(
        lambda: c.delete_user_pool_client(UserPoolId=pool_id, ClientId=good["ClientId"])
    )
    described = c.describe_user_pool_client(
        UserPoolId=pool_id, ClientId=good["ClientId"]
    )["UserPoolClient"]
    assert described["AllowedOAuthScopes"] == [valid_scope], (
        f"the positive control did not persist AllowedOAuthScopes={[valid_scope]!r}: "
        f"{described.get('AllowedOAuthScopes')!r}"
    )

    bad_client_name = ctx.unique_name("sim2real-behav-cip-client-bad-")
    code, message = _error(
        lambda: c.create_user_pool_client(
            UserPoolId=pool_id,
            ClientName=bad_client_name,
            GenerateSecret=True,
            AllowedOAuthFlows=["client_credentials"],
            AllowedOAuthScopes=[bogus_scope],
            AllowedOAuthFlowsUserPoolClient=True,
        )
    )
    assert code == "ScopeDoesNotExistException", f"expected ScopeDoesNotExistException, got {code}"
    expected_message = f"Invalid scope requested: {bogus_scope}"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Independent read at the destination: the rejected client never came into existence, and
    # only the positive control's client is present.
    clients = c.list_user_pool_clients(UserPoolId=pool_id, MaxResults=60)["UserPoolClients"]
    names = {cl["ClientName"] for cl in clients}
    assert bad_client_name not in names, (
        f"the rejected client {bad_client_name!r} exists in list_user_pool_clients: {names!r}"
    )
    assert names == {good_client_name}, (
        f"expected exactly the positive-control client {good_client_name!r} to exist, "
        f"got {names!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
