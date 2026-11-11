"""resource-server-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "resource-server-lifecycle"
GROUP = 'resource-server'
SERVICES = ['cognito-idp']

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateResourceServer / DescribeResourceServer / DeleteResourceServer full cycle."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"})["UserPool"]["Id"]
    ctx.on_cleanup(lambda _id=pool_id: c.delete_user_pool(UserPoolId=_id))
    identifier = f"https://{ctx.unique_name('sim2real-behav-cip-rs-')}.example.com"
    name = ctx.unique_name("sim2real-behav-cip-rs-")

    c.create_resource_server(
        UserPoolId=pool_id,
        Identifier=identifier,
        Name=name,
        Scopes=[{"ScopeName": "read", "ScopeDescription": "read scope"}],
    )
    desc = c.describe_resource_server(UserPoolId=pool_id, Identifier=identifier)[
        "ResourceServer"
    ]
    assert desc["Identifier"] == identifier, (
        f"expected Identifier {identifier!r}, got {desc.get('Identifier')!r}"
    )
    assert desc["Name"] == name, f"expected Name {name!r}, got {desc.get('Name')!r}"
    assert [s["ScopeName"] for s in desc.get("Scopes", [])] == ["read"], (
        f"expected a single 'read' scope, got {desc.get('Scopes')}"
    )

    c.delete_resource_server(UserPoolId=pool_id, Identifier=identifier)
    try:
        gone = c.describe_resource_server(UserPoolId=pool_id, Identifier=identifier)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"].get("Message")
    else:
        raise AssertionError(f"DescribeResourceServer after delete SUCCEEDED and returned {gone!r}")
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException after delete, got {code}"
    )
    expected_message = f"{identifier} does not exist in user pool {pool_id}."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
