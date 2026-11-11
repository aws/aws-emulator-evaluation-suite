"""op-contract-update-resource-server."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-update-resource-server"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateResourceServer actually mutates the stored Name/Scopes (verified via
    DescribeResourceServer); updating an Identifier that doesn't exist 404s."""
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    identifier = ctx.unique_name("sim2real-behav-api-")
    idp.create_resource_server(
        UserPoolId=pool_id,
        Identifier=identifier,
        Name="original-name",
        Scopes=[{"ScopeName": "read", "ScopeDescription": "read access"}],
    )

    idp.update_resource_server(
        UserPoolId=pool_id,
        Identifier=identifier,
        Name="updated-name",
        Scopes=[
            {"ScopeName": "read", "ScopeDescription": "read access"},
            {"ScopeName": "write", "ScopeDescription": "write access"},
        ],
    )

    desc = idp.describe_resource_server(UserPoolId=pool_id, Identifier=identifier)["ResourceServer"]
    assert desc["Name"] == "updated-name", desc
    scope_names = {s["ScopeName"] for s in desc["Scopes"]}
    assert scope_names == {"read", "write"}, scope_names

    missing_identifier = identifier + "-missing"
    code, message = _error(
        lambda: idp.update_resource_server(UserPoolId=pool_id, Identifier=missing_identifier, Name="x")
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected = f"{missing_identifier} does not exist in user pool {pool_id}."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
